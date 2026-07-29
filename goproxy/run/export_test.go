package run

import "time"

// SetQueryTimeoutForTest overrides the per-statement watchdog timeout so a test can exercise the
// cancellation path without waiting the configured production timeout. Test-only.
func (r *Runner) SetQueryTimeoutForTest(d time.Duration) { r.queryTimeout = d }
