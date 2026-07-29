package config

import "testing"

// Case 5: serve TLS but publish nothing, so clients verify purely against their own trust store and the
// control plane holds no certificate for the datasource. Unset — or anything unrecognized — must mean
// ADVERTISE, since that is the behavior requiring no configuration.
func TestTLSNoAdvertiseParsing(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{"", false},
		{"   ", false},
		{"0", false},
		{"false", false},
		{"nonsense", false},
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{" yes ", true},
		{"on", true},
	} {
		if got := parseBoolEnv(tc.raw); got != tc.want {
			t.Errorf("parseBoolEnv(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}
