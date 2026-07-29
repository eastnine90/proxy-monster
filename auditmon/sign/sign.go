// Package sign produces and verifies the off-box anchor signatures. The dev impl (filekey) keeps an
// ed25519 key on disk; the prod impl (kms) delegates to AWS KMS so the private key is unextractable and
// IAM-gated. The signed message is a 32-byte digest that binds BOTH the anchored id and the head hash
// (AnchorDigest), so neither field can be altered after signing without invalidating the signature.
package sign

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
)

// Signer signs a 32-byte digest and verifies such a signature. keyID identifies the key that signed; a
// verifier uses it only to select among its own configured keys (for rotation), never to trust an
// attacker-supplied key.
type Signer interface {
	Sign(digest []byte) (sig []byte, keyID string, err error)
	Verify(digest, sig []byte, keyID string) (bool, error)
}

// anchorDomainSep separates the anchor-signing digest from the row-hash construction (canon) and any other
// SHA-256 use, so a row hash can never be replayed as an anchor signature preimage.
var anchorDomainSep = []byte("pm-audit-anchor")

// acceptanceDomainSep separates an acceptance digest from an anchor digest, so neither signature can ever be
// replayed as the other: an anchor witnesses a head the monitor trusts, while an acceptance waives a break
// the monitor found. Signing one must never produce bytes that validate as the other.
var acceptanceDomainSep = []byte("pm-audit-acceptance")

// AnchorDigest is the 32-byte message an anchor's signature covers: SHA-256(domainSep ‖ u64be(upToID) ‖
// headHash). Binding upToID into the signed bytes authenticates it alongside the head hash, so an attacker
// who can write the WORM object cannot re-label a signed head under a different up_to_id.
func AnchorDigest(upToID int64, headHash []byte) []byte {
	var idBytes [8]byte
	binary.BigEndian.PutUint64(idBytes[:], uint64(upToID))
	h := sha256.New()
	h.Write(anchorDomainSep)
	h.Write(idBytes[:])
	h.Write(headHash)
	return h.Sum(nil)
}

// AcceptanceDigest is the 32-byte message an acceptance's signature covers. It binds the divergence being
// waived down to the exact bytes that disagreed — id, reason, and both hashes — so an acceptance authorizes
// precisely ONE known divergence and nothing else. Tampering that produces different bytes at the same row
// yields a different digest, so no signed acceptance covers it and the monitor still halts.
//
// resumeHash is signed too, and must be: it decides the head verification RESUMES from after stepping over
// the waived divergence, so an unsigned one could be swapped to steer the walk onto a chain the operator
// never accepted, carrying a signature that still validates.
//
// Every variable-length field is length-prefixed, so no two distinct field sets can hash to the same
// preimage by concatenation (e.g. a reason ending in hex digits could otherwise borrow bytes from the hash
// that follows it).
func AcceptanceDigest(divergentID int64, reason string, expected, actual, resumeHash []byte) []byte {
	h := sha256.New()
	h.Write(acceptanceDomainSep)
	writeU64(h, uint64(divergentID))
	writeField(h, []byte(reason))
	writeField(h, expected)
	writeField(h, actual)
	writeField(h, resumeHash)
	return h.Sum(nil)
}

func writeU64(h io.Writer, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	h.Write(b[:])
}

// writeField writes a length-prefixed field so field boundaries are unambiguous in the digest preimage.
func writeField(h io.Writer, b []byte) {
	writeU64(h, uint64(len(b)))
	h.Write(b)
}
