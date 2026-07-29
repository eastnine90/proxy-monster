package probe

import (
	"strings"
	"testing"

	sqlglot "github.com/ridi-oss/sqlglot-go"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"google.golang.org/protobuf/proto"
)

// TestNewlyParseableConservation locks in fail-closed lineage for the MySQL constructs that became
// PARSEABLE with the sqlglot-go v0.4.0 bump — MATCH(...) AGAINST(...) and GROUP_CONCAT(...
// SEPARATOR ...). Before the bump these hit PARSE→DENY (trivially safe); now they parse and are
// analyzed, so a protected column inside them MUST still surface (as a reference/origin, or the probe
// fails closed unresolved) — never silently ALLOW. This is the "newly-reachable node shape" fail-open
// class: a bump that widens parse coverage must not open a lineage hole in the constructs it unlocks.
// Each query reads users.rrn; a resolved result with rrn nowhere is a leak.
func TestNewlyParseableConservation(t *testing.T) {
	mysqlCatalog := []*pb.ColumnSpec{
		columnSpec("def", "acme", "users", "id", "BIGINT"),
		columnSpec("def", "acme", "users", "rrn", "VARCHAR"),
	}
	mysqlNs := &pb.Namespace{Catalog: "def", SearchPath: []string{"acme"}}
	const mysqlRRNKey = "def.acme.users.rrn"

	writeCatalog := []*pb.ColumnSpec{
		columnSpec("def", "acme", "users", "id", "BIGINT"),
		columnSpec("def", "acme", "users", "rrn", "VARCHAR"),
		columnSpec("def", "acme", "users", "name", "VARCHAR"),
	}

	cases := []struct {
		id      string
		sql     string
		dialect string
		catalog []*pb.ColumnSpec
		ns      *pb.Namespace
		rrnKey  string
	}{
		// MATCH(...) AGAINST(...) full-text: the searched columns are inside a DERIVED node, so a
		// protected one is not a maskable identity → must route to references (or fail closed).
		{"MATCH AGAINST (postgres)", "SELECT MATCH(rrn) AGAINST('x') FROM users", "postgres", canonicalPostgresCatalog, canonicalPostgresNamespace, canonicalUsersRRNKey},
		{"MATCH AGAINST (mysql)", "SELECT MATCH(rrn) AGAINST('x') FROM users", "mysql", mysqlCatalog, mysqlNs, mysqlRRNKey},
		{"MATCH AGAINST in WHERE (mysql)", "SELECT id FROM users WHERE MATCH(rrn) AGAINST('x' IN BOOLEAN MODE)", "mysql", mysqlCatalog, mysqlNs, mysqlRRNKey},
		// GROUP_CONCAT(... SEPARATOR ...): the aggregated value is a DERIVED node; its source column
		// must surface in all forms (plain, SEPARATOR, DISTINCT+ORDER BY).
		{"GROUP_CONCAT SEPARATOR (mysql)", "SELECT GROUP_CONCAT(rrn SEPARATOR ',') FROM users", "mysql", mysqlCatalog, mysqlNs, mysqlRRNKey},
		{"GROUP_CONCAT DISTINCT ORDER BY (mysql)", "SELECT GROUP_CONCAT(DISTINCT rrn ORDER BY rrn SEPARATOR ';') FROM users", "mysql", mysqlCatalog, mysqlNs, mysqlRRNKey},
		// A write that reads a protected column via GROUP_CONCAT must DENY, not stream it.
		{"GROUP_CONCAT in write subquery (mysql)", "UPDATE users SET name=(SELECT GROUP_CONCAT(rrn SEPARATOR ',') FROM users)", "mysql", writeCatalog, mysqlNs, mysqlRRNKey},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			engineConfig := &pb.EngineConfig{Engine: pb.Engine_POSTGRES}
			if tc.dialect == "mysql" {
				engineConfig = &pb.EngineConfig{Engine: pb.Engine_MYSQL, EngineVersion: "8.0.46", MysqlLowerCaseTableNames: proto.Int32(0)}
			}
			res := analyzeProbe(t, &pb.AnalyzeRequest{Sql: tc.sql, EngineConfig: engineConfig, Namespace: tc.ns, Catalog: tc.catalog})
			caught := !res.Resolved // unresolved = fail-closed = safe
			for _, refs := range res.References {
				for _, c := range refs {
					if c == tc.rrnKey {
						caught = true
					}
				}
			}
			for _, o := range res.Origins {
				for _, c := range o.Origins {
					if c == tc.rrnKey {
						caught = true
					}
				}
			}
			if !caught {
				t.Fatalf("LEAK — %s never surfaced (probe would ALLOW):\n  sql=%s\n  references=%v", tc.rrnKey, tc.sql, res.References)
			}
		})
	}
}

// sqlglot-go structurally parses the local MySQL INSERT ... SET and REPLACE extensions.
// These supported write shapes must reach analysis, classify as writes, and conserve protected reads;
// unresolved is fail-safe but would not prove the parser covers them.
func TestV050MySQLWriteExtensionsConserveProtectedSource(t *testing.T) {
	cols := []*pb.ColumnSpec{
		columnSpec("def", "acme", "users", "id", "BIGINT"),
		columnSpec("def", "acme", "users", "rrn", "VARCHAR"),
		columnSpec("def", "acme", "sink", "id", "BIGINT"),
		columnSpec("def", "acme", "sink", "data", "VARCHAR"),
	}
	ns := &pb.Namespace{Catalog: "def", SearchPath: []string{"acme"}}
	const rrnKey = "def.acme.users.rrn"

	cases := []struct {
		name string
		sql  string
	}{
		{"INSERT SET with scalar subquery", "INSERT INTO sink SET data=(SELECT rrn FROM users)"},
		{"REPLACE SELECT", "REPLACE INTO sink (data) SELECT rrn FROM users"},
		{"REPLACE SET with scalar subquery", "REPLACE INTO sink SET data=(SELECT rrn FROM users)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := decodeProbeResult(t, tc.sql, "mysql", cols, ns, 0)
			if !result.Resolved {
				t.Fatalf("v0.5.0 write extension must resolve, got %v: %s", stageString(result.FailedStage), result.Detail)
			}
			if !result.IsWrite {
				t.Fatalf("v0.5.0 write extension was not classified as a write: %+v", result)
			}
			if !allLineageKeys(result)[rrnKey] {
				t.Fatalf("LEAK: resolved write omitted protected source %q: origins=%v references=%v", rrnKey, result.Origins, result.References)
			}
		})
	}
}

// The root policy remains fail-closed even though v0.5.0 now gives PostgreSQL EXPLAIN a structured
// Describe root. Parsing support does not make Describe an analyzable statement root.
func TestV050PostgresExplainRemainsUnsupportedRoot(t *testing.T) {
	const sql = "EXPLAIN SELECT rrn FROM users"
	root, err := sqlglot.ParseOne(sql, "postgres")
	if err != nil {
		t.Fatalf("v0.5.0 must parse PostgreSQL EXPLAIN: %v", err)
	}
	if root.Kind() != exp.KindDescribe {
		t.Fatalf("EXPLAIN root kind = %s, want Describe", exp.ClassName(root.Kind()))
	}

	result := decodeProbeResult(t, sql, "postgres", canonicalPostgresCatalog, canonicalPostgresNamespace)
	if result.Resolved {
		t.Fatalf("Describe root must remain unresolved: %+v", result)
	}
	if result.FailedStage == nil || *result.FailedStage != "PARSE" {
		t.Fatalf("Describe root must fail at the root-policy PARSE gate: %+v", result)
	}
	if !strings.Contains(result.Detail, "unsupported root Describe") {
		t.Fatalf("Describe root denial must identify the unsupported root, got %q", result.Detail)
	}
}
