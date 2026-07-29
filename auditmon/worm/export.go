package worm

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// ExportRecord is one SIEM-bound event. It carries column identities and volumes but NOT values, and it
// represents the statement ONLY as StatementSHA256 — there is deliberately no statement-text field, so a
// SQL literal is structurally impossible to emit to the permanent store. The full SQL stays in the in-VPC
// audit_event row behind the audit.read gate; the hash is the correlation key.
type ExportRecord struct {
	ID                 int64    `json:"id"`
	Kind               string   `json:"kind"`
	TSMicros           int64    `json:"ts_micros"`
	Principal          string   `json:"principal"`
	Roles              []string `json:"roles"`
	Datasource         string   `json:"datasource"`
	ClientAddr         *string  `json:"client_addr,omitempty"`
	Decision           string   `json:"decision"`
	FailedStage        *string  `json:"failed_stage,omitempty"`
	StatementSHA256    string   `json:"statement_sha256"`
	EffectiveNamespace []string `json:"effective_namespace"`
	MaskedColumns      []string `json:"masked_columns"`
	PIITouched         []string `json:"pii_touched"`
	LatencyMs          int64    `json:"latency_ms"`
	Channel            *string  `json:"channel,omitempty"`
	ContextTags        []string `json:"context_tags"`
	AuthzAction        *string  `json:"action,omitempty"`
	AuthzResource      *string  `json:"resource,omitempty"`
	Outcome            *string  `json:"outcome,omitempty"`
	RowsReturned       *int64   `json:"rows_returned,omitempty"`
	BytesReturned      *int64   `json:"bytes_returned,omitempty"`
	DecisionID         *int64   `json:"decision_id,omitempty"`
}

// WriteEventBatch writes records as one NDJSON object per line to events/<firstID>-<lastID>.ndjson (a new
// key per batch — never an overwrite).
func WriteEventBatch(os ObjectStore, firstID, lastID int64, records []ExportRecord) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("worm: encode export record %d: %w", r.ID, err)
		}
	}
	return os.Put(fmt.Sprintf("events/%d-%d.ndjson", firstID, lastID), buf.Bytes())
}
