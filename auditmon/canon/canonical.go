// Package canon is the Go re-implementation of the audit-event canonical byte format that the Kotlin
// control plane writes. Byte-for-byte agreement between the two languages is what lets this out-of-band
// monitor re-verify the hash chain Kotlin produced; the agreement is frozen by a shared golden-vector
// suite (see canonical_test.go and control-plane's AuditCanonicalGoldenTest).
//
// Canonical bytes are DomainSep || u32be(chainVersion) || fields(event). The row-hash preimage is
// DomainSep || u32be(chainVersion) || u64be(id) || fields(event) || prevHash (prevHash exactly 32 bytes),
// and row_hash is its SHA-256. fields() encodes the 22 business columns in a fixed order with a fixed
// encoding of strings, nullables, int64s, and arrays.
package canon

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"time"
)

// ChainVersion is the canonical-format version this package encodes. Each chained row stamps the version
// that produced its hash so a verifier picks the matching field set per row.
const ChainVersion uint32 = 1

// GenesisSeed is the ASCII preimage whose SHA-256 is the pinned genesis hash the first chained row builds
// on. It is pinned off-box at install so a rewrite-from-genesis needs the off-box witness, not just DB write.
const GenesisSeed = "pm-audit-genesis"

// DomainSep separates this hash construction from any other SHA-256 use; it appears exactly once per stream.
var DomainSep = []byte("pm-audit-event")

const (
	sha256Bytes = 32
	// nullMarker is the four bytes written in place of a null scalar (Kotlin's writeInt(-1)).
	nullMarker uint32 = 0xFFFFFFFF
)

// AuditEvent is the storage-independent shape of one audited event, in the exact field order the canonical
// format encodes. It is the shared type consumed by store, verify, dbtest, and the monitor's export mapping.
type AuditEvent struct {
	Kind               string
	TSMicros           int64
	Principal          string
	Roles              []string
	Datasource         string
	ClientAddr         *string
	Statement          string
	Decision           string
	FailedStage        *string
	EffectiveNamespace []string
	MaskedColumns      []string
	PIITouched         []string
	LatencyMs          int64
	Detail             *string
	Channel            *string
	ContextTags        []string
	AuthzAction        *string
	AuthzResource      *string
	Outcome            *string
	RowsReturned       *int64
	BytesReturned      *int64
	DecisionID         *int64
}

// GenesisFromSeed is the SHA-256 of the ASCII seed, used as the head the first chained row builds on.
func GenesisFromSeed(seed string) []byte {
	sum := sha256.Sum256([]byte(seed))
	return sum[:]
}

// GenesisHash is GenesisFromSeed(GenesisSeed): 88d4f4...cd08.
func GenesisHash() []byte { return GenesisFromSeed(GenesisSeed) }

// EpochMicros truncates t to microseconds: epochSecond*1_000_000 + nanos/1_000. Nanosecond() is always in
// [0, 1e9) (like Java's getNano), so negative pre-1970 timestamps convert identically to the Kotlin side.
func EpochMicros(t time.Time) int64 {
	return t.Unix()*1_000_000 + int64(t.Nanosecond())/1_000
}

// Canonical returns DomainSep || u32be(chainVersion) || fields(ev).
func Canonical(ev AuditEvent, chainVersion uint32) []byte {
	var buf bytes.Buffer
	buf.Write(DomainSep)
	writeU32(&buf, chainVersion)
	writeFields(&buf, ev)
	return buf.Bytes()
}

// RowHash returns the SHA-256 of DomainSep || u32be(chainVersion) || u64be(id) || fields(ev) || prevHash.
// prevHash must be exactly 32 bytes.
func RowHash(id int64, ev AuditEvent, chainVersion uint32, prevHash []byte) ([]byte, error) {
	if len(prevHash) != sha256Bytes {
		return nil, fmt.Errorf("canon: prev_hash must be exactly %d bytes, got %d", sha256Bytes, len(prevHash))
	}
	var buf bytes.Buffer
	buf.Write(DomainSep)
	writeU32(&buf, chainVersion)
	writeU64(&buf, uint64(id))
	writeFields(&buf, ev)
	buf.Write(prevHash)
	sum := sha256.Sum256(buf.Bytes())
	return sum[:], nil
}

func writeFields(buf *bytes.Buffer, ev AuditEvent) {
	writeString(buf, ev.Kind)
	writeInt64(buf, ev.TSMicros)
	writeString(buf, ev.Principal)
	writeArray(buf, ev.Roles, true)
	writeString(buf, ev.Datasource)
	writeNullableString(buf, ev.ClientAddr)
	writeString(buf, ev.Statement)
	writeString(buf, ev.Decision)
	writeNullableString(buf, ev.FailedStage)
	writeArray(buf, ev.EffectiveNamespace, false)
	writeArray(buf, ev.MaskedColumns, true)
	writeArray(buf, ev.PIITouched, true)
	writeInt64(buf, ev.LatencyMs)
	writeNullableString(buf, ev.Detail)
	writeNullableString(buf, ev.Channel)
	writeArray(buf, ev.ContextTags, true)
	writeNullableString(buf, ev.AuthzAction)
	writeNullableString(buf, ev.AuthzResource)
	writeNullableString(buf, ev.Outcome)
	writeNullableInt64(buf, ev.RowsReturned)
	writeNullableInt64(buf, ev.BytesReturned)
	writeNullableInt64(buf, ev.DecisionID)
}

func writeU32(buf *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	buf.Write(b[:])
}

func writeU64(buf *bytes.Buffer, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	buf.Write(b[:])
}

func writeString(buf *bytes.Buffer, s string) {
	writeU32(buf, uint32(len(s)))
	buf.WriteString(s)
}

func writeNullableString(buf *bytes.Buffer, s *string) {
	if s == nil {
		writeU32(buf, nullMarker)
		return
	}
	writeString(buf, *s)
}

func writeInt64(buf *bytes.Buffer, v int64) {
	writeU32(buf, 8)
	writeU64(buf, uint64(v))
}

func writeNullableInt64(buf *bytes.Buffer, v *int64) {
	if v == nil {
		writeU32(buf, nullMarker)
		return
	}
	writeInt64(buf, *v)
}

// writeArray encodes u32be(count) then each element as u32be(len)||UTF-8. Set-valued arrays sort ascending
// by unsigned byte order (bytes.Compare == Kotlin's UNSIGNED_UTF8_COMPARATOR) with duplicates preserved.
func writeArray(buf *bytes.Buffer, values []string, sortSet bool) {
	encoded := make([][]byte, len(values))
	for i, v := range values {
		encoded[i] = []byte(v)
	}
	if sortSet {
		sort.SliceStable(encoded, func(i, j int) bool { return bytes.Compare(encoded[i], encoded[j]) < 0 })
	}
	writeU32(buf, uint32(len(encoded)))
	for _, e := range encoded {
		writeU32(buf, uint32(len(e)))
		buf.Write(e)
	}
}
