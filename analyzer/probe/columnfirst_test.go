package probe

import (
	"testing"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// TestColumnFirstCanonical locks in PG column-first resolution (chain-walked) against the
// docs/relation-model.md canonical PoCs + variants — the column-first leak family:
// a bare name PG binds column-first to an outer/target protected column, or to a relation-valued
// column, was mis-bound to a same-named decoy alias and streamed cleartext. Every case reads
// users.rrn, so the probe MUST catch it (DENY via references, or fail-closed unresolved). A resolved
// case with users.rrn nowhere is a leak.
func TestColumnFirstCanonical(t *testing.T) {
	cases := []struct{ id, sql string }{
		// canonical PoCs
		{"#1 write correlated (SELECT rrn)", "UPDATE users u SET name=(SELECT rrn) FROM orders rrn WHERE u.id=rrn.user_id"},
		{"#2 write subquery-own-FROM", "UPDATE users u SET name=(SELECT rrn FROM orders rrn LIMIT 1) WHERE u.id=1"},
		{"#3 write jsonb-of-target-row", "UPDATE users u SET name=(SELECT to_jsonb(u)::text) FROM orders rrn WHERE u.id=rrn.user_id"},
		{"#4 write decoy-alias vs relation-valued", "UPDATE sink SET data=((sub).rrn)::text FROM orders sub CROSS JOIN (SELECT users AS sub FROM users) d WHERE sink.id=1"},
		{"#5 read correlated scalar-subquery", "SELECT (SELECT rrn FROM orders rrn LIMIT 1) AS x FROM users u"},
		// variants
		{"read decoy Dot (u).rrn with alias", "SELECT (sub).rrn AS x FROM (SELECT users AS sub FROM users) d, orders sub"},
		{"read correlated in WHERE", "SELECT u.id FROM users u WHERE u.id = (SELECT rrn FROM orders rrn LIMIT 1)::bigint"},
		{"write decoy in RETURNING", "UPDATE sink SET data='x' FROM orders sub CROSS JOIN (SELECT users AS sub FROM users) d WHERE sink.id=1 RETURNING (sub).rrn"},
		// quoted identifiers (case-sensitive PG): resolution must match AS-IS, not lowercase
		{"quoted relation-valued", `SELECT (d."sub").rrn AS x FROM (SELECT users AS "sub" FROM users) d`},
		{"quoted decoy vs alias", `SELECT ("Sub").rrn AS x FROM (SELECT users AS "Sub" FROM users) d, orders "Sub"`},
		// write-side conservation (docs/relation-model.md): a protected read in ANY orphaned write clause
		// — SET / RETURNING / VALUES / MERGE-action / ON CONFLICT — across ALL roots, not just UPDATE SET
		{"MERGE SET bare-correlated", "MERGE INTO users u USING orders rrn ON u.id=rrn.user_id WHEN MATCHED THEN UPDATE SET name=(SELECT rrn)"},
		{"MERGE SET whole-row", "MERGE INTO users u USING orders o ON u.id=o.user_id WHEN MATCHED THEN UPDATE SET name=(SELECT to_jsonb(u)::text)"},
		{"ON CONFLICT SET whole-row", "INSERT INTO users (id,name) VALUES (1,'y') ON CONFLICT (id) DO UPDATE SET name=(SELECT to_jsonb(u)::text FROM users u WHERE u.id=excluded.id)"},
		{"DELETE RETURNING correlated", "DELETE FROM users u USING orders rrn WHERE u.id=rrn.user_id RETURNING u.id,(SELECT rrn)"},
		{"UPDATE RETURNING correlated", "UPDATE users u SET name='x' FROM orders rrn WHERE u.id=rrn.user_id RETURNING (SELECT rrn)"},
		{"INSERT VALUES subquery decoy", "INSERT INTO sink (id,data) VALUES (1,(SELECT rrn FROM users, orders rrn LIMIT 1))"},
		{"DELETE RETURNING via USING", "DELETE FROM sink USING users u, orders rrn WHERE sink.id=u.id RETURNING (SELECT rrn)"},
		// composite field access on a scalar-subquery-returning-a-row base (no decoy needed)
		{"read subquery-base Dot", "SELECT (SELECT u FROM users u LIMIT 1).rrn AS x"},
		{"UPDATE SET subquery-base Dot", "UPDATE sink SET data=(SELECT u FROM users u LIMIT 1).rrn WHERE sink.id=1"},
		{"DELETE RETURNING subquery-base", "DELETE FROM sink u WHERE u.id=1 RETURNING (SELECT u2 FROM users u2 LIMIT 1).rrn"},
		// RETURNING on a SELECT-bodied write (outside the payload SELECT) must still be swept
		{"INSERT…SELECT RETURNING correlated", "INSERT INTO sink (id,data) SELECT u.id,'x' FROM users u RETURNING id,(SELECT rrn FROM users, orders rrn LIMIT 1)"},
		{"INSERT…SELECT RETURNING subquery-base", "INSERT INTO sink (id,data) SELECT 100,'x' RETURNING (SELECT u FROM users u LIMIT 1).rrn AS leaked"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			res := analyzeProbe(t, &pb.AnalyzeRequest{Sql: tc.sql, EngineConfig: &pb.EngineConfig{Engine: pb.Engine_POSTGRES}, Namespace: canonicalPostgresNamespace, Catalog: canonicalPostgresCatalog})
			caught := !res.Resolved
			for _, cols := range res.References {
				for _, c := range cols {
					if c == canonicalUsersRRNKey {
						caught = true
					}
				}
			}
			for _, o := range res.Origins {
				for _, c := range o.Origins {
					if c == canonicalUsersRRNKey {
						caught = true
					}
				}
			}
			if !caught {
				t.Fatalf("LEAK — users.rrn never surfaced (probe would ALLOW):\n  sql=%s\n  references=%v", tc.sql, res.References)
			}
		})
	}
}
