package main

import "testing"

// TestSplitArgs covers every invocation shape an operator or container CMD actually uses. The daemon's own
// documented form (`auditmon -config <path>`, flag value as a separate argv entry) is the one that matters
// most: getting it wrong means the monitor does not start at all, and nothing else in the suite would notice.
func TestSplitArgs(t *testing.T) {
	tests := []struct {
		name     string
		argv     []string
		wantCmd  string
		wantRest []string
	}{
		{"no arguments runs the daemon", nil, "", nil},
		{"space-separated flag value is not a subcommand",
			[]string{"-config", "auditmon.yaml"}, "", []string{"-config", "auditmon.yaml"}},
		{"double-dash flag form",
			[]string{"--config", "auditmon.yaml"}, "", []string{"--config", "auditmon.yaml"}},
		{"equals flag form",
			[]string{"-config=auditmon.yaml"}, "", []string{"-config=auditmon.yaml"}},
		{"subcommand alone", []string{"verify"}, "verify", nil},
		{"subcommand then flag",
			[]string{"verify", "-config", "x.yaml"}, "verify", []string{"-config", "x.yaml"}},
		{"accept-break with a flag",
			[]string{"accept-break", "-config=x.yaml"}, "accept-break", []string{"-config=x.yaml"}},
		// A flag VALUE that happens to spell a subcommand must stay a value: the subcommand is positional.
		{"a flag value spelling a subcommand is still a value",
			[]string{"-config", "verify"}, "", []string{"-config", "verify"}},
		{"explicit run", []string{"run"}, "run", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd, rest := splitArgs(tc.argv)
			if cmd != tc.wantCmd {
				t.Errorf("cmd = %q, want %q", cmd, tc.wantCmd)
			}
			if len(rest) != len(tc.wantRest) {
				t.Fatalf("rest = %q, want %q", rest, tc.wantRest)
			}
			for i := range rest {
				if rest[i] != tc.wantRest[i] {
					t.Fatalf("rest = %q, want %q", rest, tc.wantRest)
				}
			}
		})
	}
}
