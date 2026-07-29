package detect

import "strings"

// SQL-shape heuristics over the statement text. They are deliberately coarse: detection is an alerting aid,
// not an authorization gate (Cedar is the per-query gate), so a rough leading-keyword classification is
// enough to bucket a statement as a read or a write and to spot a broad, unbounded read.
//
// Known blind spots of the leading-keyword approach: a data-modifying CTE (WITH ... DELETE/UPDATE/INSERT ...
// RETURNING) classifies as a read because WITH leads, and a statement that opens with a parenthesis (a
// parenthesized SELECT, or a leading comment that this skips only for -- and /* forms) may not match any
// keyword. This is acceptable because these heuristics never gate access — Cedar does — and the PII rules
// key on the analyzer-derived pii_touched, not on statement shape; the shape only tunes the mass-export
// degradation and off_hours read/write bucketing, where a miss is a softer or missed alert, never a bypass.

// writeKeywords are leading keywords that mutate data or schema.
var writeKeywords = map[string]struct{}{
	"INSERT": {}, "UPDATE": {}, "DELETE": {}, "MERGE": {}, "REPLACE": {},
	"CREATE": {}, "ALTER": {}, "DROP": {}, "TRUNCATE": {}, "RENAME": {},
	"GRANT": {}, "REVOKE": {}, "CALL": {}, "SET": {}, "LOAD": {}, "COPY": {},
}

// readKeywords are leading keywords that only read.
var readKeywords = map[string]struct{}{
	"SELECT": {}, "WITH": {}, "SHOW": {}, "TABLE": {}, "VALUES": {},
	"DESCRIBE": {}, "DESC": {}, "EXPLAIN": {},
}

// leadingKeyword returns the upper-cased first SQL keyword, skipping a leading line/block comment and
// whitespace.
func leadingKeyword(stmt string) string {
	s := strings.TrimSpace(stmt)
	for {
		switch {
		case strings.HasPrefix(s, "--"):
			if i := strings.IndexByte(s, '\n'); i >= 0 {
				s = strings.TrimSpace(s[i+1:])
				continue
			}
			return ""
		case strings.HasPrefix(s, "/*"):
			if i := strings.Index(s, "*/"); i >= 0 {
				s = strings.TrimSpace(s[i+2:])
				continue
			}
			return ""
		}
		break
	}
	end := strings.IndexFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '(' || r == ';'
	})
	if end < 0 {
		end = len(s)
	}
	return strings.ToUpper(s[:end])
}

// isWrite reports whether the statement mutates data or schema.
func isWrite(stmt string) bool {
	_, ok := writeKeywords[leadingKeyword(stmt)]
	return ok
}

// isRead reports whether the statement only reads.
func isRead(stmt string) bool {
	_, ok := readKeywords[leadingKeyword(stmt)]
	return ok
}

// isBroadRead is the mass-export degradation heuristic: a read with no LIMIT clause, i.e. a potentially
// unbounded scan. It stands in for result volume only until the proxy's post-execution completion event
// (which carries the true rows/bytes) is available for the window.
func isBroadRead(stmt string) bool {
	return isRead(stmt) && !strings.Contains(strings.ToLower(stmt), "limit")
}
