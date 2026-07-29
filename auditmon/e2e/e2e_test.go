//go:build e2e

// TestE2E drives real SQL through the pmon broker against the LIVE demo stack and asserts the audit monitor
// turns the resulting audit trail into WORM alerts. It is the true end-to-end path: pmon (pinned TLS to the
// proxy) -> wire proxy -> control-plane Decide -> audit_event -> auditmon poll -> detect -> WORM alerts/.
//
// It assumes the demo is already up AND that `pmon login` has run (the daemon holds a broker port + the
// wire token for the logged-in principal); launch/login are out of scope. Run:
//
//	AUDITMON_E2E=1 go test -tags e2e -run TestE2E$ -timeout 20m ./e2e/...
//
// Every target (datasource, PII table/column, counts) is env-overridable so the run tunes to the live
// demo's data + rule thresholds without a code change — see targetsFromEnv.
package e2e

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql" // registers the "mysql" driver for sql.Open
	"github.com/jackc/pgx/v5/pgxpool"
)

// targets are the demo-specific query subjects. Defaults comfortably exceed the SHIPPED rule thresholds
// (config/testdata/monitor.yaml: repeated_deny max_deny 20, bulk_pii max_pii_decisions 200, mass_export
// heuristic_max_broad_reads 50); if the target deployment tunes them lower, set the *_COUNT envs to just
// over its values so the run stays fast.
type targets struct {
	datasource string // MySQL datasource name (as `pmon status` shows it)
	piiTable   string // a table the principal may read that has a PII-classified column
	piiColumn  string // a PII-classified column on piiTable
	readTable  string // a table the principal may `SELECT *` (broad read) — defaults to piiTable
	denySQL    string // a statement that reliably DENY/ERRORs for the principal (default: a missing table)

	denyCount  int // > repeated_deny.max_deny
	piiCount   int // > bulk_pii.max_pii_decisions
	broadCount int // > mass_export.heuristic_max_broad_reads
}

func targetsFromEnv() targets {
	piiTable := env("AUDITMON_E2E_PII_TABLE", "users")
	tg := targets{
		datasource: env("AUDITMON_E2E_DS", "acme-mysql"),
		piiTable:   piiTable,
		piiColumn:  env("AUDITMON_E2E_PII_COL", "email"),
		readTable:  env("AUDITMON_E2E_READ_TABLE", piiTable),
		denySQL:    env("AUDITMON_E2E_DENY_SQL", "SELECT 1 FROM __pm_e2e_no_such_table__ LIMIT 1"),
		denyCount:  envInt("AUDITMON_E2E_DENY_COUNT", 25),
		piiCount:   envInt("AUDITMON_E2E_PII_COUNT", 205),
		broadCount: envInt("AUDITMON_E2E_BROAD_COUNT", 55),
	}
	return tg
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return def
}

// pmonBrokerDSN shells out to `pmon show <ds> --go-dsn` — literally the connection pmon hands out — which
// prints a go-sql-driver DSN for the datasource's local broker (sticky port + injected wire token + pinned
// upstream TLS). This proves the whole broker path, not a direct proxy dial.
func pmonBrokerDSN(t *testing.T, pmonBin, datasource string) string {
	t.Helper()
	out, err := exec.Command(pmonBin, "show", datasource, "--go-dsn").Output()
	if err != nil {
		t.Fatalf("pmon show %s --go-dsn: %v (is the daemon running + logged in?)", datasource, err)
	}
	return strings.TrimSpace(string(out))
}

func TestE2E(t *testing.T) {
	if os.Getenv("AUDITMON_E2E") == "" {
		t.Skip("set AUDITMON_E2E=1 to run the live-demo end-to-end alert test")
	}
	c := demoCoords()
	tg := targetsFromEnv()
	pmonBin := env("AUDITMON_E2E_PMON", "pmon")
	ctx := context.Background()

	// This test asserts on the DELTA — the alerts that appear because of the traffic it drives — and
	// deliberately does NOT reset the audit chain or wipe the WORM prefixes.
	//
	// Resetting was the original design and it was wrong three ways, each of which produced a run that
	// generated perfect traffic and then failed for reasons that had nothing to do with detection:
	// truncating restarts ids at 1, which is BELOW the monitor's in-memory export watermark, so every fresh
	// row reads as already-exported and no rule ever evaluates; a signed checkpoint left over from the old
	// chain makes the monitor's from-genesis re-verify conclude tampering and halt outright; and the alert
	// sink's dedup window suppresses a repeat for the same principal regardless. The first two are only
	// escapable by restarting the monitor, which makes the test depend on someone else's process lifecycle.
	//
	// Deltas avoid all of it and test the truer thing: production auditmon never sees its trail truncated —
	// ids only grow — so a long-running monitor with real history IS the deployed shape. The one state that
	// still needs care is the sink's dedup window, so the run uses a distinct principal (see targets).
	before, err := readWormAlerts(c)
	if err != nil {
		t.Fatalf("read WORM alerts (baseline): %v", err)
	}
	seen := make(map[string]bool, len(before))
	for _, a := range before {
		seen[a.Key] = true
	}
	t.Logf("baseline: %d alert objects already in WORM; asserting on what THIS run adds", len(before))

	// Connect THROUGH the pmon broker — the point of the test.
	db, err := sql.Open("mysql", pmonBrokerDSN(t, pmonBin, tg.datasource))
	if err != nil {
		t.Fatalf("open pmon broker connection: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(2)
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping via pmon broker (demo up? logged in? cert pin ok?): %v", err)
	}

	// Drive each rate rule with real queries over the broker. Per-query errors on the deny path are expected
	// (that IS the signal); PII/broad reads should succeed (masked reads still record pii_touched).
	driveDenies(t, db, tg)
	drivePIIReads(t, db, tg)
	driveBroadReads(t, db, tg)

	t.Logf("drove %d denies, %d PII reads, %d broad reads via pmon %q; waiting %s for the monitor poll",
		tg.denyCount, tg.piiCount, tg.broadCount, tg.datasource, c.pollWait)
	time.Sleep(c.pollWait)

	after, err := readWormAlerts(c)
	if err != nil {
		t.Fatalf("read WORM alerts: %v", err)
	}
	alerts := make([]wormAlert, 0, len(after))
	for _, a := range after {
		if !seen[a.Key] {
			alerts = append(alerts, a)
		}
	}
	fired := rulesFired(alerts)
	t.Logf("NEW WORM alerts from this run: %v (%d new of %d total)", fired, len(alerts), len(after))
	if len(alerts) == 0 {
		// Traffic demonstrably landed (counts above) yet the monitor emitted nothing new. The causes are
		// invisible from both the DB and the bucket because they live in the monitor's memory — name them
		// rather than leaving several identical "no alert for X" failures to be puzzled over.
		t.Errorf("the monitor emitted NO new alerts, though the traffic landed (counts above). Likely causes: " +
			"(1) alert dedup — this principal was already alerted on within alerts.dedup_window, so re-run past " +
			"it or log in as a different principal via `pmon login`; (2) the monitor is halted on a " +
			"chain-break (its log says so explicitly) — check for a stale signed checkpoint; (3) its in-memory " +
			"export watermark is above these rows' ids, which happens if the audit chain was reset or restored " +
			"underneath a running monitor.")
	}

	wantRule(t, alerts, "repeated_deny")
	wantRule(t, alerts, "bulk_pii")
	// mass_export is deliberately NOT asserted. Once the proxy ships completion events (this deployment
	// does), the rule judges real result VOLUME and the broad-read count is only the fallback for a
	// deployment without them. A demo-sized table (a handful of rows) can never reach a rows/bytes ceiling
	// meant for a real export, so demanding the alert here would assert the detector is wrong. Exercising a
	// genuine mass export needs a fixture large enough to cross the configured ceiling — see
	// AUDITMON_E2E_BROAD_COUNT and the rows threshold in the monitor config.

	// off_hours can only fire from a live query when the wall clock is actually outside business hours; the
	// PII reads above are pii_reads, so it fires for free when the run happens off-hours. Assert only then.
	if offHoursNow(t) {
		wantRule(t, alerts, "off_hours")
	} else {
		t.Log("skipping off_hours assertion: run is within business hours (09:00-19:00 Asia/Seoul)")
	}
}

// driveDenies runs a reliably-denied statement denyCount times so the principal accumulates > max_deny
// DENY/ERROR decisions in the window. A missing table fails closed at the control plane for any principal,
// so this needs no grant knowledge; LIMIT keeps it off the mass_export broad-read heuristic.
func driveDenies(t *testing.T, db *sql.DB, tg targets) {
	for i := 0; i < tg.denyCount; i++ {
		_, _ = db.Exec(tg.denySQL) // expected to error (DENY/ERROR) — that is the signal
	}
}

// drivePIIReads reads a PII-classified column piiCount times so the principal touches PII across
// > max_pii_decisions decisions. LIMIT 1 keeps each a bounded (non-broad) read so only bulk_pii is tripped.
func drivePIIReads(t *testing.T, db *sql.DB, tg targets) {
	q := fmt.Sprintf("SELECT %s FROM %s LIMIT 1", tg.piiColumn, tg.piiTable)
	for i := 0; i < tg.piiCount; i++ {
		rows, err := db.Query(q)
		if err != nil {
			t.Fatalf("PII read %q failed (wrong table/column, or no connect grant?): %v", q, err)
		}
		rows.Close()
	}
}

// driveBroadReads runs an unbounded SELECT * (no LIMIT) broadCount times so the principal+datasource exceeds
// mass_export's broad-read heuristic (the volume path fires instead, at Critical, if the demo ships
// completion events and the table is over the row/byte ceiling).
func driveBroadReads(t *testing.T, db *sql.DB, tg targets) {
	q := fmt.Sprintf("SELECT * FROM %s", tg.readTable)
	for i := 0; i < tg.broadCount; i++ {
		rows, err := db.Query(q)
		if err != nil {
			t.Fatalf("broad read %q failed (wrong table, or no connect grant?): %v", q, err)
		}
		rows.Close()
	}
}

// wantRule fails the test unless at least one WORM alert fired for rule.
func wantRule(t *testing.T, alerts []wormAlert, rule string) {
	t.Helper()
	for _, a := range alerts {
		if a.Rule == rule {
			t.Logf("OK  %-14s severity=%s principal=%s ds=%s ids=%v", a.Rule, a.Severity, a.Principal, a.Datasource, a.DecisionIDs)
			return
		}
	}
	t.Errorf("no WORM alert for rule %q (fired: %v)", rule, distinctRules(alerts))
}

func distinctRules(alerts []wormAlert) []string {
	seen := map[string]struct{}{}
	for _, a := range alerts {
		seen[a.Rule] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// offHoursNow reports whether the current wall clock is outside the shipped business window
// (09:00-19:00 Asia/Seoul, weekdays) — the same span the demo's off_hours rule uses.
func offHoursNow(t *testing.T) bool {
	t.Helper()
	loc, err := time.LoadLocation("Asia/Seoul")
	if err != nil {
		t.Logf("load Asia/Seoul: %v; treating as business hours", err)
		return false
	}
	now := time.Now().In(loc)
	if now.Weekday() == time.Saturday || now.Weekday() == time.Sunday {
		return true
	}
	minute := now.Hour()*60 + now.Minute()
	return minute < 9*60 || minute >= 19*60
}

// TestIntegrityBreakAndRecovery is the audit subsystem's headline property, end to end against a real
// deployment: corrupt a committed row, watch the monitor notice, watch it refuse to keep witnessing, and then
// walk the documented operator recovery back to a working monitor.
//
// It is DESTRUCTIVE in a way the delta test is not — it deliberately breaks the chain, and a break is
// permanent: afterwards the trail carries a real divergence and a real integrity alert, exactly as it would
// after a genuine incident. That is why it is opt-in twice over (AUDITMON_E2E plus an explicit
// AUDITMON_E2E_BIN/CONFIG pointing at the monitor whose chain may be broken) rather than running by default.
func TestIntegrityBreakAndRecovery(t *testing.T) {
	if os.Getenv("AUDITMON_E2E") == "" {
		t.Skip("set AUDITMON_E2E=1 to run the live end-to-end tests")
	}
	c := demoCoords()
	if c.auditmonBin == "" || c.auditmonCfg == "" {
		t.Skip("set AUDITMON_E2E_BIN and AUDITMON_E2E_CONFIG to run the destructive integrity test " +
			"(it breaks the target's audit chain permanently)")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, c.pgDSN)
	if err != nil {
		t.Fatalf("connect audit store: %v", err)
	}
	// t.Cleanup, NOT defer: the tamper is undone from a t.Cleanup below, and every deferred call in this
	// function runs BEFORE any t.Cleanup. A deferred Close would therefore shut the pool out from under the
	// restore and leave the target's chain broken. Cleanups run last-registered-first, so registering
	// Close here (before the restore is registered) guarantees the pool outlives it.
	t.Cleanup(pool.Close)

	// Baseline: the operator's own tool must agree the trail is intact BEFORE we break it. Without this the
	// test could "detect" a break that was already there and prove nothing.
	//
	// Skipping is only correct for an ALREADY-BROKEN trail. A config, DB, or bucket failure also makes verify
	// exit non-zero, and skipping on that would turn every misconfiguration into a silent pass — the drill
	// would report success while never having run. So distinguish them: a real break names its reason.
	if out, err := runAuditmon(t, c, "verify"); err != nil {
		if strings.Contains(out, "AUDIT TRAIL BROKEN") {
			t.Skipf("the target trail is already broken, so this test cannot prove detection: %v\n%s", err, out)
		}
		t.Fatalf("baseline `auditmon verify` could not run (not a chain break — check the config, DSN env, and "+
			"bucket reachability): %v\n%s", err, out)
	}

	// Corrupt one committed row in place: the classic edit-the-evidence tamper. The row keeps its stored
	// row_hash, which no longer matches its content, so the chain walk must catch it.
	var victim int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM audit_event WHERE kind = 'decision' ORDER BY id DESC LIMIT 1 OFFSET 5`).Scan(&victim); err != nil {
		t.Fatalf("pick a row to corrupt: %v", err)
	}
	var original string
	if err := pool.QueryRow(ctx, `SELECT principal FROM audit_event WHERE id = $1`, victim).Scan(&original); err != nil {
		t.Fatalf("read original principal: %v", err)
	}
	// The tamper content must be UNIQUE per run. An acceptance is permanent and is scoped to the exact bytes
	// that diverged, so writing the same principal into the same row twice reproduces a divergence a previous
	// run already accepted — correctly waived, and therefore no longer detectable. That is the acceptance model
	// working as intended, but it would make this drill a one-shot against any given bucket.
	tampered := fmt.Sprintf("e2e-tamper-%d", time.Now().UnixNano())

	// Register the restore BEFORE the tamper, not after. This tamper is exactly reversible — only `principal`
	// changes and row_hash is left alone — and the restore must run on EVERY exit path, including a t.Fatalf or
	// a timeout landing between the UPDATE and its registration. Registering afterwards leaves a window where a
	// failure abandons the target with a broken chain; the monitor then halts on its next pass and every later
	// run skips at the baseline check instead of reporting anything. Accepting a break is the right answer when
	// history genuinely cannot be recovered, and the wrong one when a single UPDATE puts it back.
	//
	// Restoring unconditionally is safe: if the tamper never landed, this rewrites the value that is already
	// there.
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(),
			`UPDATE audit_event SET principal = $1 WHERE id = $2`, original, victim); err != nil {
			t.Errorf("COULD NOT RESTORE audit_event id=%d to principal %q: %v — the target's chain is left "+
				"broken; restore it manually or run `auditmon accept-break` on the monitor host",
				victim, original, err)
			return
		}
		t.Logf("restored audit_event id=%d to principal %q; the chain verifies again", victim, original)
	})

	if _, err := pool.Exec(ctx,
		`UPDATE audit_event SET principal = $1 WHERE id = $2`, tampered, victim); err != nil {
		t.Fatalf("corrupt row %d: %v", victim, err)
	}
	t.Logf("corrupted audit_event id=%d (principal %q -> %q)", victim, original, tampered)

	// DETECT: the operator's read-only command names the row and the reason, and fails loudly.
	out, err := runAuditmon(t, c, "verify")
	if err == nil {
		t.Fatalf("`auditmon verify` reported the trail intact AFTER a row was corrupted — detection failed:\n%s", out)
	}
	if !strings.Contains(out, "row_hash_mismatch") {
		t.Errorf("verify did not report row_hash_mismatch for an in-place edit; got:\n%s", out)
	}
	if !strings.Contains(out, fmt.Sprint(victim)) {
		t.Errorf("verify did not name the corrupted row id %d; got:\n%s", victim, out)
	}

	// The anchor covering the break, recorded BEFORE recovery: accepting a break must never overwrite the
	// witness that proved it, so this exact object has to survive byte-for-byte.
	witness, err := highestCheckpoint(t, c)
	if err != nil {
		t.Fatalf("read the witnessing checkpoint: %v", err)
	}

	// RECOVER: accept the break. This records a signed acceptance and brings coverage forward.
	if out, err := runAuditmon(t, c, "accept-break"); err != nil {
		t.Fatalf("`auditmon accept-break` failed: %v\n%s", err, out)
	}

	// The divergence is still REPORTED — it re-walks from genesis every time, so a break that happened is
	// visible forever — but now as an ACCEPTED one rather than an outstanding break. Accepting resumes
	// monitoring; it must never make the history look clean. An operator who saw the divergence disappear
	// would reasonably conclude the trail had been repaired, which would be a lie.
	out, err = runAuditmon(t, c, "verify")
	if err != nil {
		t.Errorf("verify still reports an UNACCEPTED break after accept-break:\n%s", out)
	}
	if !strings.Contains(out, "ACCEPTED chain divergence") {
		t.Errorf("verify stopped reporting the accepted divergence; an accepted break must stay visible:\n%s", out)
	}
	if !strings.Contains(out, fmt.Sprint(victim)) {
		t.Errorf("verify no longer names the accepted row %d:\n%s", victim, out)
	}

	// The witness that proved the break is still there, unchanged.
	if after, err := checkpointBody(t, c, witness.key); err != nil {
		t.Errorf("the checkpoint %s that witnessed the break is unreadable after accept-break: %v", witness.key, err)
	} else if after != witness.body {
		t.Errorf("accept-break OVERWROTE the checkpoint %s that witnessed the break; the off-box evidence of "+
			"the divergence is gone", witness.key)
	}

	// What recovery restores is FORWARD coverage, and the honest proof is that the monitor witnesses a row that
	// arrived AFTER the accept. A rising checkpoint id alone does not show that: at an unchanged head there is
	// nothing new to anchor, so "no higher id" is the correct outcome rather than a failure. Drive one real
	// decision through and require the anchor to advance over it.
	headBefore, err := chainHeadID(ctx, pool)
	if err != nil {
		t.Fatalf("read chain head: %v", err)
	}
	if err := driveOneDecision(t, c); err != nil {
		t.Skipf("could not drive a post-recovery decision (needs a logged-in pmon daemon), so forward coverage "+
			"is unproven here — the monitor's own tests cover it: %v", err)
	}
	// EXPORT, not the anchor, is the observable that moves on a demo-usable timescale. A resumed monitor
	// exports on every poll (30s in the demo config) but signs a new anchor only on sign_interval, which is
	// minutes — so waiting for the checkpoint to advance would fail a perfectly healthy monitor. A halted
	// monitor does neither: Poll returns early before exporting, which is exactly what makes the export feed a
	// faithful proxy for "is it witnessing again".
	deadline := time.Now().Add(c.pollWait + 90*time.Second)
	for {
		headNow, err := chainHeadID(ctx, pool)
		if err != nil {
			t.Fatalf("read chain head: %v", err)
		}
		exportedThrough, err := highestExportedID(t, c)
		if err != nil {
			t.Fatalf("read the export feed after recovery: %v", err)
		}
		if headNow > headBefore && exportedThrough >= headNow {
			t.Logf("monitoring resumed: rows through id %d arrived after the accept and are exported off-box "+
				"(pre-accept anchor witness was %d, still intact)", headNow, witness.id)
			break
		}
		if time.Now().After(deadline) {
			t.Errorf("the monitor did not export rows that arrived after the accept: head %d (was %d), exported "+
				"through %d — a halted monitor exports nothing, so forward coverage did not return",
				headNow, headBefore, exportedThrough)
			break
		}
		time.Sleep(5 * time.Second)
	}

	// Recovery accepts the break; it never edits the trail. (The t.Cleanup above is the TEST restoring its own
	// tamper afterwards, which is a different actor from the monitor.)
	var after string
	if err := pool.QueryRow(ctx, `SELECT principal FROM audit_event WHERE id = $1`, victim).Scan(&after); err != nil {
		t.Fatalf("re-read the corrupted row: %v", err)
	}
	if after != tampered {
		t.Errorf("row %d principal = %q; recovery must accept the break, never rewrite the trail", victim, after)
	}
}

// runAuditmon invokes the monitor's own CLI the way an operator would, returning its combined output so a
// failure shows what the operator would have read.
func runAuditmon(t *testing.T, c coords, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(c.auditmonBin, append(args, "-config", c.auditmonCfg)...)
	// The config names the DSN by env var rather than embedding it (it is a secret), so the operator command
	// needs that variable set the same way the daemon's own environment sets it.
	cmd.Env = append(os.Environ(),
		"AUDITMON_DB_DSN="+c.pgDSN,
		"AWS_ACCESS_KEY_ID="+c.minioKey,
		"AWS_SECRET_ACCESS_KEY="+c.minioSec,
		"AWS_REGION=us-east-1",
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// highestExportedID returns the greatest event id the monitor has exported off-box, read from the batch keys
// (events/<firstID>-<lastID>.ndjson). It compares the parsed LAST id numerically — these keys must never be
// ordered lexicographically, where "events/552-1098" sorts after "events/2200-2210" despite being far older.
func highestExportedID(t *testing.T, c coords) (int64, error) {
	t.Helper()
	if err := mcAlias(c); err != nil {
		return 0, err
	}
	out, err := exec.Command("mc", "ls", "--recursive", "--json",
		fmt.Sprintf("e2e/%s/events/", c.wormBucket)).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("list export batches: %v: %s", err, out)
	}
	var best int64
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		var entry struct {
			Key string `json:"key"`
		}
		if json.Unmarshal([]byte(line), &entry) != nil || entry.Key == "" {
			continue
		}
		name := strings.TrimSuffix(path.Base(entry.Key), ".ndjson")
		_, lastID, ok := strings.Cut(name, "-")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(lastID, 10, 64)
		if err == nil && n > best {
			best = n
		}
	}
	return best, nil
}

// chainHeadID reads the write path's current append point — the highest committed event id.
func chainHeadID(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	var id int64
	err := pool.QueryRow(ctx, `SELECT last_id FROM audit_chain_head WHERE id = 1`).Scan(&id)
	return id, err
}

// driveOneDecision puts a single real decision through the pmon broker so the trail grows after recovery.
// It reports an error rather than failing the test: without a logged-in daemon there is nothing to drive, and
// that is a missing precondition, not a recovery defect.
func driveOneDecision(t *testing.T, c coords) error {
	t.Helper()
	tg := targetsFromEnv()
	out, err := exec.Command(env("AUDITMON_E2E_PMON", "pmon"), "show", tg.datasource, "--go-dsn").Output()
	if err != nil {
		return fmt.Errorf("pmon show %s --go-dsn: %w", tg.datasource, err)
	}
	db, err := sql.Open("mysql", strings.TrimSpace(string(out)))
	if err != nil {
		return fmt.Errorf("open broker connection: %w", err)
	}
	defer db.Close()
	// Any DECISION grows the chain — a DENY is audited exactly like an ALLOW, including a denial issued at
	// connect time before a statement is ever sent. So this needs no grant on any table, and a
	// "denied: no access to datasource" error means the decision path RAN and recorded a row, which is
	// precisely what the caller needs. Only a failure to reach the proxy at all means nothing was driven;
	// requiring a successful SELECT would couple the drill to the demo's grants for no added coverage.
	var discard any
	err = db.QueryRow(tg.denySQL).Scan(&discard)
	if err == nil || isProxyDecision(err) {
		return nil
	}
	return fmt.Errorf("could not reach the proxy to drive a decision: %w", err)
}

// isProxyDecision reports whether an error came from proxy-monster's own decision path (an audited DENY)
// rather than from failing to reach it. A recorded denial is a decision, and a decision grows the chain.
func isProxyDecision(err error) bool {
	return strings.Contains(err.Error(), "proxy-monster denied")
}

// checkpoint identifies one signed anchor object plus its bytes, so a test can prove the object survived a
// recovery unchanged rather than merely that something with a high id exists.
type checkpoint struct {
	id   int64
	key  string
	body string
}

// highestCheckpoint returns the anchor with the greatest up_to_id currently in the bucket.
func highestCheckpoint(t *testing.T, c coords) (checkpoint, error) {
	t.Helper()
	if err := mcAlias(c); err != nil {
		return checkpoint{}, err
	}
	out, err := exec.Command("mc", "ls", "--recursive", "--json",
		fmt.Sprintf("e2e/%s/checkpoints/", c.wormBucket)).CombinedOutput()
	if err != nil {
		return checkpoint{}, fmt.Errorf("list checkpoints: %v: %s", err, out)
	}
	best := checkpoint{id: -1}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		var entry struct {
			Key string `json:"key"`
		}
		if json.Unmarshal([]byte(line), &entry) != nil || entry.Key == "" {
			continue
		}
		name := strings.TrimSuffix(path.Base(entry.Key), ".json")
		// ParseInt, not Sscanf: Sscanf("%d") would accept "1234abc" and silently treat junk as an anchor id.
		n, err := strconv.ParseInt(name, 10, 64)
		if err != nil || n <= best.id {
			continue
		}
		best = checkpoint{id: n, key: "checkpoints/" + path.Base(entry.Key)}
	}
	if best.id < 0 {
		return checkpoint{}, fmt.Errorf("no checkpoint objects under checkpoints/")
	}
	body, err := checkpointBody(t, c, best.key)
	if err != nil {
		return checkpoint{}, err
	}
	best.body = body
	return best, nil
}

// checkpointBody reads one checkpoint object's bytes.
func checkpointBody(t *testing.T, c coords, key string) (string, error) {
	t.Helper()
	if err := mcAlias(c); err != nil {
		return "", err
	}
	out, err := exec.Command("mc", "cat", fmt.Sprintf("e2e/%s/%s", c.wormBucket, key)).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("mc cat %s: %v: %s", key, err, out)
	}
	return string(out), nil
}
