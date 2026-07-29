package canon

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// goldenEvent unmarshals the fixture with typed int64 fields. It must never use map[string]interface{} or
// generic JSON numbers: float64 would corrupt the int64-min/max vectors.
type goldenEvent struct {
	TS                 string   `json:"ts"`
	Principal          string   `json:"principal"`
	Roles              []string `json:"roles"`
	Datasource         string   `json:"datasource"`
	ClientAddr         *string  `json:"clientAddr"`
	Statement          string   `json:"statement"`
	Decision           string   `json:"decision"`
	FailedStage        *string  `json:"failedStage"`
	EffectiveNamespace []string `json:"effectiveNamespace"`
	MaskedColumns      []string `json:"maskedColumns"`
	PIITouched         []string `json:"piiTouched"`
	LatencyMs          int64    `json:"latencyMs"`
	Detail             *string  `json:"detail"`
	Channel            *string  `json:"channel"`
	ContextTags        []string `json:"contextTags"`
	AuthzAction        *string  `json:"authzAction"`
	AuthzResource      *string  `json:"authzResource"`
	Outcome            *string  `json:"outcome"`
	Kind               string   `json:"kind"`
	RowsReturned       *int64   `json:"rowsReturned"`
	BytesReturned      *int64   `json:"bytesReturned"`
	DecisionID         *int64   `json:"decisionId"`
}

type goldenCase struct {
	Name         string      `json:"name"`
	ID           int64       `json:"id"`
	PrevHashHex  string      `json:"prevHashHex"`
	Event        goldenEvent `json:"event"`
	CanonicalHex string      `json:"canonicalHex"`
	RowHashHex   string      `json:"rowHashHex"`
}

type goldenFixture struct {
	DomainSep    string       `json:"domainSep"`
	ChainVersion uint32       `json:"chainVersion"`
	Cases        []goldenCase `json:"cases"`
}

func (e goldenEvent) toAuditEvent(t *testing.T) AuditEvent {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, e.TS)
	if err != nil {
		t.Fatalf("parse ts %q: %v", e.TS, err)
	}
	return AuditEvent{
		Kind:               e.Kind,
		TSMicros:           EpochMicros(ts),
		Principal:          e.Principal,
		Roles:              e.Roles,
		Datasource:         e.Datasource,
		ClientAddr:         e.ClientAddr,
		Statement:          e.Statement,
		Decision:           e.Decision,
		FailedStage:        e.FailedStage,
		EffectiveNamespace: e.EffectiveNamespace,
		MaskedColumns:      e.MaskedColumns,
		PIITouched:         e.PIITouched,
		LatencyMs:          e.LatencyMs,
		Detail:             e.Detail,
		Channel:            e.Channel,
		ContextTags:        e.ContextTags,
		AuthzAction:        e.AuthzAction,
		AuthzResource:      e.AuthzResource,
		Outcome:            e.Outcome,
		RowsReturned:       e.RowsReturned,
		BytesReturned:      e.BytesReturned,
		DecisionID:         e.DecisionID,
	}
}

// TestCanonicalGoldenVectors reads the SAME fixture the Kotlin CI asserts and checks canonical bytes AND
// row_hash for every vector. If it passes, Kotlin-write and Go-verify agree byte-for-byte; if it fails,
// the format drifted and the chain would falsely read as tampered.
func TestCanonicalGoldenVectors(t *testing.T) {
	path := filepath.Join("..", "..", "control-plane", "src", "test", "resources", "atrail", "canonical-golden.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden fixture %s: %v", path, err)
	}
	var fx goldenFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal golden fixture: %v", err)
	}

	if fx.DomainSep != string(DomainSep) {
		t.Fatalf("domainSep = %q, want %q", fx.DomainSep, DomainSep)
	}
	if fx.ChainVersion != ChainVersion {
		t.Fatalf("chainVersion = %d, want %d", fx.ChainVersion, ChainVersion)
	}
	if len(fx.Cases) != 6 {
		t.Fatalf("cases = %d, want 6", len(fx.Cases))
	}

	for _, c := range fx.Cases {
		ev := c.Event.toAuditEvent(t)

		gotCanon := hex.EncodeToString(Canonical(ev, fx.ChainVersion))
		if gotCanon != c.CanonicalHex {
			t.Errorf("[%s] canonical bytes:\n got  %s\n want %s", c.Name, gotCanon, c.CanonicalHex)
		}

		prev, err := hex.DecodeString(c.PrevHashHex)
		if err != nil {
			t.Fatalf("[%s] decode prevHashHex: %v", c.Name, err)
		}
		got, err := RowHash(c.ID, ev, fx.ChainVersion, prev)
		if err != nil {
			t.Fatalf("[%s] RowHash: %v", c.Name, err)
		}
		if gotHex := hex.EncodeToString(got); gotHex != c.RowHashHex {
			t.Errorf("[%s] row hash:\n got  %s\n want %s", c.Name, gotHex, c.RowHashHex)
		}
	}
}

func TestRowHashRejectsWrongPrevHashLength(t *testing.T) {
	if _, err := RowHash(1, AuditEvent{Decision: "ALLOW"}, ChainVersion, make([]byte, 31)); err == nil {
		t.Fatal("expected an error for a 31-byte prev_hash, got nil")
	}
}

func TestGenesisHash(t *testing.T) {
	const want = "88d4f4719f26cf7f32839ac30b1d6a94edf3f9133fb75667d1415fff81bbcd08"
	if got := hex.EncodeToString(GenesisHash()); got != want {
		t.Fatalf("GenesisHash() = %s, want %s", got, want)
	}
}
