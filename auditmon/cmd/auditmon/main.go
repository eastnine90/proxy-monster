// Command auditmon is the CP-independent audit monitor: it reads the committed audit trail read-only,
// re-verifies the hash chain, exports redacted event batches to a WORM object store, and periodically signs
// an off-box anchor. It never writes to the database and never blocks a decision.
//
// Subcommands:
//
//	auditmon                  run the monitor (default)
//	auditmon verify           re-verify now and report what, if anything, diverged; exits non-zero on a break
//	auditmon accept-break     ACCEPT a chain break: re-anchor over the current head so monitoring resumes
//
// verify and accept-break are the operator recovery path, and they are deliberately COMMANDS ON THIS HOST
// rather than an API. The monitor is the watcher of a system it does not trust; if the control plane could
// call "resume", a compromised control plane could tamper with the trail and then silence the monitor that
// noticed. Recovery therefore requires someone with access to the monitor host itself.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/ridi-oss/proxy-monster/auditmon/alert"
	"github.com/ridi-oss/proxy-monster/auditmon/canon"
	"github.com/ridi-oss/proxy-monster/auditmon/config"
	"github.com/ridi-oss/proxy-monster/auditmon/detect"
	"github.com/ridi-oss/proxy-monster/auditmon/monitor"
	"github.com/ridi-oss/proxy-monster/auditmon/sign"
	"github.com/ridi-oss/proxy-monster/auditmon/store"
	"github.com/ridi-oss/proxy-monster/auditmon/verify"
	"github.com/ridi-oss/proxy-monster/auditmon/worm"
)

func main() {
	if err := run(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run() error {
	cmd, args := splitArgs(os.Args[1:])
	// Reject an unknown subcommand before loading config or opening anything, so a typo reports the usage
	// rather than whatever the first unrelated failure happens to be.
	switch cmd {
	case "", "run", "verify", "accept-break":
	default:
		return fmt.Errorf("unknown subcommand %q (want: run, verify, accept-break)", cmd)
	}

	fs := flag.NewFlagSet("auditmon", flag.ContinueOnError)
	configPath := fs.String("config", envOr("AUDITMON_CONFIG", "auditmon.yaml"), "path to the monitor config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Refuse leftover words rather than ignoring them: `auditmon accept-break verify` must not quietly run the
	// destructive accept because the second word was dropped on the floor.
	if rest := fs.Args(); len(rest) > 0 {
		return fmt.Errorf("unexpected argument %q (subcommand must come first: auditmon [run|verify|accept-break] [flags])", rest[0])
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	dsn, err := cfg.DBDSN()
	if err != nil {
		return err
	}
	reader, err := store.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer reader.Close()

	// Only the daemon may mint a dev signing key on first start. verify/accept-break must fail on a missing
	// key instead: a fresh identity would verify none of the existing anchors, so every off-box witness would
	// be dropped and a tampered trail could read as intact.
	signer, err := buildSigner(ctx, cfg.Monitor, cmd == "" || cmd == "run")
	if err != nil {
		return err
	}

	objStore, err := worm.NewS3(ctx, worm.S3Config{
		Bucket:   cfg.Monitor.Bucket,
		Endpoint: cfg.Monitor.Endpoint,
	})
	if err != nil {
		return err
	}

	alertSink, err := alert.New(cfg.Alerts, objStore)
	if err != nil {
		return err
	}
	detector, err := detect.New(reader, alertSink, cfg.Rules)
	if err != nil {
		return err
	}
	reporter := alert.NewReporter(alertSink)

	// The chain's fixed starting link. Not configurable: the control plane's copy is written into
	// audit_chain_head by a migration, and the two must be the same 32 bytes or verification reports a
	// break on an intact chain.
	genesis := canon.GenesisHash()
	m := monitor.New(reader, signer, objStore, genesis, cfg.Monitor, detector, reporter)

	switch cmd {
	case "verify":
		return verifyOnce(ctx, m)
	case "accept-break":
		return acceptBreak(ctx, m)
	case "", "run":
		// fall through to the monitor loop
	default:
		return fmt.Errorf("unknown subcommand %q (want: run, verify, accept-break)", cmd)
	}

	slog.Info("audit monitor starting",
		"bucket", cfg.Monitor.Bucket,
		"poll_interval", cfg.Monitor.PollInterval.String(),
		"sign_interval", cfg.Monitor.SignInterval.String(),
		"signer", cfg.Monitor.Signer.Type,
		"alert_sinks", len(cfg.Alerts.Sinks),
	)
	if err := m.Run(ctx); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

func buildSigner(ctx context.Context, cfg config.MonitorConfig, mayGenerate bool) (sign.Signer, error) {
	switch cfg.Signer.Type {
	case "filekey":
		if !mayGenerate {
			return sign.OpenFileKey(cfg.Signer.KeyPath)
		}
		return sign.NewFileKey(cfg.Signer.KeyPath)
	case "kms":
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, err
		}
		return sign.NewKMS(kms.NewFromConfig(awsCfg), cfg.Signer.KeyID, cfg.Signer.AllowedKeyIDs...), nil
	default:
		// Unreachable: config.Validate already rejects any other signer type.
		return nil, nil
	}
}

// splitArgs separates an optional leading subcommand from the flags that follow it. The subcommand is
// POSITIONAL — first or not at all — because a bare word appearing after a flag is ambiguous: `-config verify`
// could be the verify subcommand or the config path, and guessing wrong swallows the flag's value and stops
// the daemon from starting.
func splitArgs(argv []string) (cmd string, rest []string) {
	if len(argv) > 0 && !strings.HasPrefix(argv[0], "-") {
		return argv[0], argv[1:]
	}
	return "", argv
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// verifyOnce re-verifies the whole chain and reports the result. It is READ-ONLY: it neither alerts nor
// changes the monitor's state, so an operator can ask "is the trail intact, and if not, where and how did it
// diverge?" as many times as they need. A break exits non-zero so it composes with scripts and health checks.
func verifyOnce(ctx context.Context, m *monitor.Monitor) error {
	d, err := m.Diagnose(ctx)
	if err != nil {
		return err
	}
	// Previously-accepted divergences are reported every time: accepting a break resumes monitoring, it never
	// makes the history look clean.
	for _, a := range d.Accepted {
		slog.Warn("ACCEPTED chain divergence stands in the history",
			"divergent_id", a.DivergentID, "reason", a.Reason)
	}
	f := d.Finding
	if f == nil {
		if len(d.Accepted) > 0 {
			slog.Info("no unaccepted divergence remains; the accepted ones above are permanent history")
			return nil
		}
		slog.Info("audit trail verified intact from genesis")
		return nil
	}
	slog.Error("AUDIT TRAIL BROKEN", "divergent_id", f.DivergentID, "reason", f.Reason)
	// Say what the reason MEANS, because the recovery decision differs by cause and the operator reading this
	// is probably reading it for the first time, in an incident.
	switch f.Reason {
	case verify.ReasonRowHashMismatch:
		slog.Error("a stored row's content no longer matches its own hash: that row was edited in place")
	case verify.ReasonPrevHashMismatch:
		slog.Error("a row's link to its predecessor is broken: rows were deleted, reordered, or inserted")
	case verify.ReasonAnchorRowMissing:
		slog.Error("a signed anchor witnessed rows the trail no longer reaches: rows at or below it were deleted or truncated")
	case verify.ReasonAnchorHeadMismatch:
		slog.Error("the chain recomputes cleanly but disagrees with a signed anchor: the trail was rewritten wholesale, " +
			"and the off-box signature is what proves it")
	case verify.ReasonMissingChainVersion:
		slog.Error("a chained row carries no chain_version: a pre-chain row appears after an anchored head, " +
			"which the chain cannot account for")
	case monitor.ReasonAnchorSignatureInvalid:
		slog.Error("no signed anchor validates: the off-box witnesses are missing or forged, so the trail CANNOT " +
			"be judged intact — a rewritten chain verifies clean on its own")
	}
	slog.Warn("nothing repairs a break: restore the trail from backup if you have one, or run " +
		"`auditmon accept-break` to accept this divergence and resume monitoring")
	slog.Warn("note: verification always re-walks from genesis, so this command keeps reporting a past break " +
		"even after it is accepted — that is intended, an accepted break stays visible")
	return errChainBroken
}

// acceptBreak is the deliberate operator decision to accept a chain break and resume forward monitoring. It
// records a signed acceptance off-box, then brings coverage forward: the rows that arrived while the monitor
// was halted are exported before a fresh anchor is signed, so the halted window is not silently dropped from
// the SIEM. The running daemon resumes on its own next full pass by reading the same acceptance.
func acceptBreak(ctx context.Context, m *monitor.Monitor) error {
	d, err := m.Diagnose(ctx)
	if err != nil {
		return err
	}
	if d.Finding == nil {
		slog.Info("no unaccepted chain break; nothing to accept")
		return nil
	}
	rec, err := m.AcceptBreak(ctx, *d.Finding)
	if err != nil {
		if monitor.ErrNothingToAccept(err) {
			slog.Info("no unaccepted chain break; nothing to accept")
			return nil
		}
		return err
	}
	slog.Warn("chain break ACCEPTED — the break itself remains in the record permanently",
		"accepted_divergent_id", rec.DivergentID, "accepted_reason", rec.Reason)
	if err := m.ResumeCoverage(ctx); err != nil {
		// The acceptance is durably recorded, so the daemon will still resume; only bringing the export/anchor
		// forward from THIS process failed. Say so precisely rather than implying the accept did not take.
		slog.Error("acceptance recorded, but bringing coverage forward from this process failed; "+
			"the running monitor still resumes on its next full verification", "err", err)
		return err
	}
	slog.Warn("halted-window rows exported and a fresh anchor signed; a running monitor resumes on its next " +
		"full verification")
	return nil
}

var errChainBroken = errors.New("audit trail integrity check failed")
