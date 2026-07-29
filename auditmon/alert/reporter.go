package alert

import (
	"time"

	"github.com/ridi-oss/proxy-monster/auditmon/config"
	"github.com/ridi-oss/proxy-monster/auditmon/verify"
)

// Reporter adapts a chain-integrity finding into a critical alert and delivers it through the same Sink as
// the anomaly rules, so integrity and anomaly alerts share one durable + notification path. It satisfies the
// monitor's IntegrityReporter hook.
type Reporter struct {
	sink *Sink
}

// NewReporter builds a Reporter delivering through sink.
func NewReporter(sink *Sink) *Reporter { return &Reporter{sink: sink} }

// Report turns a verify.Finding into an integrity Alert. The divergent row id rides in DecisionIDs; the
// finding is always critical because a broken chain means the trail can no longer be trusted intact.
func (r *Reporter) Report(f verify.Finding) {
	r.sink.Deliver(Alert{
		Severity:    config.SeverityCritical,
		Rule:        config.RuleIntegrity,
		DecisionIDs: []int64{f.DivergentID},
		TS:          time.Now(),
	})
}
