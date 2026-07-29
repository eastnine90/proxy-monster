package worm

import (
	"errors"
	"strings"
	"testing"
)

func TestMemoryPutListGet(t *testing.T) {
	store := NewMemory()
	if err := store.Put("events/1-2.ndjson", []byte("payload")); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := store.Put("checkpoints/1.json", []byte("{}")); err != nil {
		t.Fatalf("put: %v", err)
	}

	keys, err := store.List("events/")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 || keys[0] != "events/1-2.ndjson" {
		t.Fatalf("list events/ = %v", keys)
	}

	body, err := store.Get("events/1-2.ndjson")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(body) != "payload" {
		t.Fatalf("get body = %q", body)
	}

	if _, err := store.Get("missing"); err == nil {
		t.Fatal("expected error getting a missing object")
	}
}

func TestReadAnchorsReturnsAllAscending(t *testing.T) {
	store := NewMemory()
	for _, a := range []Anchor{
		{UpToID: 5, HeadHash: "aa", Signature: "c2ln", KeyID: "k1"},
		{UpToID: 42, HeadHash: "bb", Signature: "c2ln", KeyID: "k1"},
		{UpToID: 12, HeadHash: "cc", Signature: "c2ln", KeyID: "k1"},
	} {
		if err := WriteAnchor(store, a); err != nil {
			t.Fatalf("write anchor %d: %v", a.UpToID, err)
		}
	}

	got, err := ReadAnchors(store)
	if err != nil {
		t.Fatalf("read anchors: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("read %d anchors, want 3: %+v", len(got), got)
	}
	if got[0].UpToID != 5 || got[1].UpToID != 12 || got[2].UpToID != 42 {
		t.Fatalf("anchors not ascending by up_to_id: %+v", got)
	}
	if got[2].HeadHash != "bb" {
		t.Fatalf("highest anchor = %+v, want head bb at up_to_id 42", got[2])
	}
}

// TestWriteAnchorRefusesToOverwriteADifferingWitness is the storage-level guarantee behind the monitor's
// tamper evidence. For an internally-consistent rewrite from genesis the signed anchor is the ONLY thing that
// proves the trail changed — the row-walk comes back clean — so replacing that object with a signature over
// the current head launders the rewrite under the monitor's own key. One object per id means any anchor write
// at an id that already has a DIFFERENT witness must fail rather than clobber it, whatever the caller.
//
// The narrower rule (only recovery must not overwrite) is not enough: whichever code path advances an anchor
// at an unchanged head id hits the same key, so the refusal belongs here, at the write.
func TestWriteAnchorRefusesToOverwriteADifferingWitness(t *testing.T) {
	store := NewMemory()
	witness := Anchor{UpToID: 9, HeadHash: "aa", Signature: "c2ln", KeyID: "k1"}
	if err := WriteAnchor(store, witness); err != nil {
		t.Fatalf("write the original anchor: %v", err)
	}

	// A different head at the same id: this is the laundering write.
	err := WriteAnchor(store, Anchor{UpToID: 9, HeadHash: "ff", Signature: "c2ln", KeyID: "k1"})
	if err == nil {
		t.Fatal("WriteAnchor replaced the witness at up_to_id 9 with a different head; the only off-box " +
			"evidence of a consistent rewrite can be overwritten")
	}

	// …and the original is untouched.
	got, readErr := ReadAnchors(store)
	if readErr != nil {
		t.Fatalf("read anchors: %v", readErr)
	}
	if len(got) != 1 || got[0].HeadHash != "aa" {
		t.Fatalf("anchors = %+v, want the original witness (head aa) intact", got)
	}
}

// TestWriteAnchorIsIdempotentForTheSameHead confirms re-signing an UNCHANGED head is not an error: a poll and
// a sign tick at the same head both write the same anchor, and that must not fail the monitor.
func TestWriteAnchorIsIdempotentForTheSameHead(t *testing.T) {
	store := NewMemory()
	a := Anchor{UpToID: 9, HeadHash: "aa", Signature: "c2ln", KeyID: "k1"}
	if err := WriteAnchor(store, a); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := WriteAnchor(store, a); err != nil {
		t.Fatalf("re-writing the identical anchor must be allowed, got: %v", err)
	}
}

// TestReadAnchorsSkipsJunkObject confirms a checkpoint object with an unparseable body is skipped rather
// than failing the whole read — one junk object (undeletable under Object-Lock) must not wedge the monitor.
func TestReadAnchorsSkipsJunkObject(t *testing.T) {
	store := NewMemory()
	if err := WriteAnchor(store, Anchor{UpToID: 7, HeadHash: "aa", Signature: "c2ln", KeyID: "k1"}); err != nil {
		t.Fatalf("write anchor: %v", err)
	}
	if err := store.Put("checkpoints/99999999.json", []byte("not json at all")); err != nil {
		t.Fatalf("put junk: %v", err)
	}

	got, err := ReadAnchors(store)
	if err != nil {
		t.Fatalf("read anchors: %v", err)
	}
	if len(got) != 1 || got[0].UpToID != 7 {
		t.Fatalf("read anchors = %+v, want only the parseable one (up_to_id 7)", got)
	}
}

func TestReadAnchorsEmpty(t *testing.T) {
	got, err := ReadAnchors(NewMemory())
	if err != nil {
		t.Fatalf("read anchors: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no anchors, got %+v", got)
	}
}

func TestWriteEventBatchIsNDJSONWithHashNotStatement(t *testing.T) {
	store := NewMemory()
	records := []ExportRecord{
		{ID: 1, Kind: "decision", Principal: "alice", Datasource: "warehouse", Decision: "ALLOW",
			StatementSHA256: "deadbeef", Roles: []string{}, EffectiveNamespace: []string{}, MaskedColumns: []string{}, PIITouched: []string{}, ContextTags: []string{}},
		{ID: 2, Kind: "decision", Principal: "bob", Datasource: "warehouse", Decision: "DENY",
			StatementSHA256: "cafebabe", Roles: []string{}, EffectiveNamespace: []string{}, MaskedColumns: []string{}, PIITouched: []string{}, ContextTags: []string{}},
	}
	if err := WriteEventBatch(store, 1, 2, records); err != nil {
		t.Fatalf("write batch: %v", err)
	}

	keys, err := store.List("events/")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 || keys[0] != "events/1-2.ndjson" {
		t.Fatalf("keys = %v, want events/1-2.ndjson", keys)
	}

	body, err := store.Get(keys[0])
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("ndjson lines = %d, want 2", len(lines))
	}
	text := string(body)
	if !strings.Contains(text, "deadbeef") || !strings.Contains(text, "statement_sha256") {
		t.Fatalf("batch missing statement hash: %s", text)
	}
	// The batch must never carry SQL text: there is no statement field at all.
	if strings.Contains(text, "\"statement\"") {
		t.Fatalf("batch leaked a statement field: %s", text)
	}
}

// failingGetStore wraps a store and makes Get fail with a non-not-found error for one key, modelling a
// throttle, an outage, or a denied read.
type failingGetStore struct {
	ObjectStore
	failKey string
}

func (f failingGetStore) Get(key string) ([]byte, error) {
	if key == f.failKey {
		return nil, errors.New("worm: get: connection reset")
	}
	return f.ObjectStore.Get(key)
}

// TestWriteAnchorFailsClosedWhenTheExistingObjectCannotBeRead is the difference between a guard that holds and
// one that merely usually holds. "Absent" and "unreadable" are not the same: if a Get failure were treated as
// absence, a single throttled read would let a differing head be written straight over a witness the call
// never saw — reinstating the evidence destruction this guard exists to prevent, with no attacker needed
// beyond ordinary flakiness. A missed anchor is recoverable; an overwritten one is not.
func TestWriteAnchorFailsClosedWhenTheExistingObjectCannotBeRead(t *testing.T) {
	backing := NewMemory()
	witness := Anchor{UpToID: 9, HeadHash: "aa", Signature: "c2ln", KeyID: "k1"}
	if err := WriteAnchor(backing, witness); err != nil {
		t.Fatalf("seed the witness: %v", err)
	}

	blind := failingGetStore{ObjectStore: backing, failKey: checkpointPrefix + "9.json"}
	if err := WriteAnchor(blind, Anchor{UpToID: 9, HeadHash: "ff", Signature: "c2ln", KeyID: "k1"}); err == nil {
		t.Fatal("WriteAnchor wrote a differing head while it could not read what was already there; an " +
			"unreadable object was treated as an absent one, so a transient read failure destroys evidence")
	}

	// The witness is intact on the real store underneath.
	got, err := ReadAnchors(backing)
	if err != nil {
		t.Fatalf("read anchors: %v", err)
	}
	if len(got) != 1 || got[0].HeadHash != "aa" {
		t.Fatalf("anchors = %+v, want the original witness (head aa) intact", got)
	}
}

// TestWriteAnchorWritesWhenTheKeyIsGenuinelyAbsent confirms failing closed on unreadable does not also block
// the ordinary first write, which must still succeed against an empty bucket.
func TestWriteAnchorWritesWhenTheKeyIsGenuinelyAbsent(t *testing.T) {
	store := NewMemory()
	if err := WriteAnchor(store, Anchor{UpToID: 3, HeadHash: "aa", Signature: "c2ln", KeyID: "k1"}); err != nil {
		t.Fatalf("first anchor into an empty bucket must succeed, got: %v", err)
	}
}

// TestWriteAnchorRefusesWhenTheExistingObjectIsUnreadableJunk pins that junk at a checkpoint key blocks the
// write instead of being treated as a free slot.
//
// On a versioned store an unparseable current object is not evidence that no witness exists — it can be junk
// PUT over a real anchor, whose retained version still holds the evidence while every read path here sees only
// the current version. Replacing it would sign a fresh head over a key whose true witness is invisible, which
// is laundering with one extra step. Reading may skip junk (one bad object must not wedge verification);
// writing over it must not.
func TestWriteAnchorRefusesWhenTheExistingObjectIsUnreadableJunk(t *testing.T) {
	store := NewMemory()
	if err := store.Put(checkpointPrefix+"9.json", []byte("not an anchor")); err != nil {
		t.Fatalf("plant junk: %v", err)
	}
	// The head is deliberately EMPTY so this cannot be satisfied by the differing-head check: an unparseable
	// body unmarshals to the zero Anchor, whose HeadHash is also empty, so only an explicit refusal on
	// unreadable content can reject this write. Without that distinction the test would pass on the wrong
	// branch and prove nothing about junk handling.
	if err := WriteAnchor(store, Anchor{UpToID: 9, HeadHash: "", Signature: "c2ln", KeyID: "k1"}); err == nil {
		t.Fatal("WriteAnchor replaced an unreadable object at a checkpoint key; junk there may be concealing a " +
			"retained witness, so writing over it can launder a rewrite")
	}
	// The junk is left exactly as found — the point is to stop and be looked at, not to tidy up.
	body, err := store.Get(checkpointPrefix + "9.json")
	if err != nil || string(body) != "not an anchor" {
		t.Fatalf("object at the checkpoint key = %q (err %v), want it untouched", body, err)
	}
}
