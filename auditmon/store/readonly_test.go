package store

import (
	"context"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/auditmon/canon"
	"github.com/ridi-oss/proxy-monster/auditmon/internal/dbtest"
)

// TestReaderRefusesWrites confirms the defense-in-depth read-only session rejects any write, so a bug that
// tried to mutate the trail would fail loudly rather than silently tamper with what it is meant to watch.
func TestReaderRefusesWrites(t *testing.T) {
	ctx := context.Background()
	pool, dsn := dbtest.OpenPostgres(t)
	dbtest.ApplySchema(t, ctx, pool)
	dbtest.SeedChain(t, ctx, pool, canon.GenesisHash(), []canon.AuditEvent{{
		Kind: "decision", Principal: "a", Datasource: "d", Statement: "q1", Decision: "ALLOW",
		TSMicros: canon.EpochMicros(time.Now()),
	}})

	reader, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer reader.Close()

	if _, err := reader.pool.Exec(ctx, "DELETE FROM audit_event"); err == nil {
		t.Fatal("expected the read-only session to reject DELETE, but it succeeded")
	}
}
