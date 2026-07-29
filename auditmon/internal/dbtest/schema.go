package dbtest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/auditmon/canon"
)

// SchemaDDL is the shape of the two audit tables (audit_event and audit_chain_head). Tests apply it
// directly instead of running Flyway.
const SchemaDDL = `
CREATE TABLE audit_event (
    id                  BIGINT PRIMARY KEY,
    ts                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    principal           TEXT NOT NULL,
    roles               JSONB NOT NULL DEFAULT '[]',
    datasource          TEXT NOT NULL,
    client_addr         TEXT,
    statement           TEXT NOT NULL,
    decision            TEXT NOT NULL,
    failed_stage        TEXT,
    masked_columns      JSONB NOT NULL DEFAULT '[]',
    pii_touched         JSONB NOT NULL DEFAULT '[]',
    latency_ms          BIGINT NOT NULL DEFAULT 0,
    detail              TEXT,
    effective_namespace JSONB NOT NULL DEFAULT '[]',
    channel             TEXT,
    context_tags        JSONB NOT NULL DEFAULT '[]',
    action              TEXT,
    resource            TEXT,
    outcome             TEXT,
    kind                TEXT NOT NULL DEFAULT 'decision',
    rows_returned       BIGINT,
    bytes_returned      BIGINT,
    decision_id         BIGINT REFERENCES audit_event(id),
    chain_version       INT,
    prev_hash           BYTEA,
    row_hash            BYTEA
);

CREATE TABLE audit_chain_head (
    id        INT PRIMARY KEY CHECK (id = 1),
    last_id   BIGINT NOT NULL,
    head_hash BYTEA NOT NULL
);
`

// ApplySchema creates the audit tables in the pool's database (each OpenPostgres gives a fresh database, so
// there is nothing to drop first).
func ApplySchema(t testing.TB, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, SchemaDDL); err != nil {
		t.Fatalf("apply schema: %v", err)
	}
}

// InsertEvent writes one audit_event row verbatim (the caller supplies the already-computed prev/row
// hashes and chain version, exactly as the Kotlin write path would have committed them).
func InsertEvent(t testing.TB, ctx context.Context, pool *pgxpool.Pool, id int64, ev canon.AuditEvent, prevHash, rowHash []byte, chainVersion int32) {
	t.Helper()
	const q = `
INSERT INTO audit_event (
    id, ts, principal, roles, datasource, client_addr, statement, decision, failed_stage,
    masked_columns, pii_touched, latency_ms, detail, effective_namespace, channel, context_tags,
    action, resource, outcome, kind, rows_returned, bytes_returned, decision_id,
    chain_version, prev_hash, row_hash
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9,
    $10, $11, $12, $13, $14, $15, $16,
    $17, $18, $19, $20, $21, $22, $23,
    $24, $25, $26
)`
	_, err := pool.Exec(ctx, q,
		id,
		time.UnixMicro(ev.TSMicros).UTC(),
		ev.Principal,
		jsonArray(ev.Roles),
		ev.Datasource,
		ev.ClientAddr,
		ev.Statement,
		ev.Decision,
		ev.FailedStage,
		jsonArray(ev.MaskedColumns),
		jsonArray(ev.PIITouched),
		ev.LatencyMs,
		ev.Detail,
		jsonArray(ev.EffectiveNamespace),
		ev.Channel,
		jsonArray(ev.ContextTags),
		ev.AuthzAction,
		ev.AuthzResource,
		ev.Outcome,
		ev.Kind,
		ev.RowsReturned,
		ev.BytesReturned,
		ev.DecisionID,
		chainVersion,
		prevHash,
		rowHash,
	)
	if err != nil {
		t.Fatalf("insert event %d: %v", id, err)
	}
}

// SetChainHead upserts the singleton audit_chain_head row.
func SetChainHead(t testing.TB, ctx context.Context, pool *pgxpool.Pool, lastID int64, headHash []byte) {
	t.Helper()
	const q = `
INSERT INTO audit_chain_head (id, last_id, head_hash) VALUES (1, $1, $2)
ON CONFLICT (id) DO UPDATE SET last_id = EXCLUDED.last_id, head_hash = EXCLUDED.head_hash`
	if _, err := pool.Exec(ctx, q, lastID, headHash); err != nil {
		t.Fatalf("set chain head: %v", err)
	}
}

// SeedChain inserts events as a valid hash chain built from genesis, sets audit_chain_head to the final
// head, and returns the last id and head hash. Each event's id is its 1-based position. An empty slice
// leaves the greenfield initial state (last_id 0, head = genesis).
func SeedChain(t testing.TB, ctx context.Context, pool *pgxpool.Pool, genesis []byte, events []canon.AuditEvent) (lastID int64, head []byte) {
	t.Helper()
	return AppendChain(t, ctx, pool, 1, genesis, events)
}

// AppendChain continues an existing hash chain: it inserts events with ids startID, startID+1, ... chained
// from prev, updates audit_chain_head to the new final head, and returns the last id and head hash. It lets
// a test grow a tail after an earlier SeedChain, e.g. to simulate rows landing between a poll and a sign.
func AppendChain(t testing.TB, ctx context.Context, pool *pgxpool.Pool, startID int64, prev []byte, events []canon.AuditEvent) (lastID int64, head []byte) {
	t.Helper()
	lastID = startID - 1
	for i, ev := range events {
		id := startID + int64(i)
		rh, err := canon.RowHash(id, ev, canon.ChainVersion, prev)
		if err != nil {
			t.Fatalf("row hash for id %d: %v", id, err)
		}
		InsertEvent(t, ctx, pool, id, ev, prev, rh, int32(canon.ChainVersion))
		prev = rh
		lastID = id
	}
	SetChainHead(t, ctx, pool, lastID, prev)
	return lastID, prev
}

// jsonArray renders a []string as a JSONB array literal. A nil/empty slice must render as "[]" (not the
// "null" that json.Marshal would emit) to satisfy the NOT NULL + jsonb-array-typed columns.
func jsonArray(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}
