package dbtest

import "testing"

// imageSeries decides whether a run is version-checked at all, so a parsing slip that returns "" turns
// the check off silently — the failure mode is a leg that passes without verifying anything. These
// cases pin the forms that must resolve and the forms that legitimately cannot.
func TestImageSeries(t *testing.T) {
	for _, tc := range []struct {
		img  string
		want string
	}{
		{"mysql:8.0", "8.0"},
		{"mysql:8.4", "8.4"},
		{"postgres:16", "16"},
		{"postgres:17", "17"},
		// A variant suffix is not part of the series the server reports.
		{"postgres:16-alpine", "16"},
		{"postgres:17.6-bookworm", "17.6"},
		// A registry port is not a tag: the colon precedes the last slash.
		{"localhost:5000/postgres", ""},
		{"localhost:5000/postgres:16", "16"},
		{"registry.example.com:5000/team/postgres:17", "17"},
		// Nothing to pin.
		{"postgres", ""},
		{"postgres:latest", ""},
		{"postgres:", ""},
	} {
		if got := imageSeries(tc.img); got != tc.want {
			t.Errorf("imageSeries(%q) = %q, want %q", tc.img, got, tc.want)
		}
	}
}
