package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

// fileKey is the dev signer: an ed25519 key stored as its 32-byte seed in a 0600 file.
type fileKey struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID string
}

// NewFileKey loads the ed25519 key at path, generating and writing a fresh one (mode 0600) if the file is
// absent. An existing file must be exactly the seed and mode 0600, or NewFileKey errors.
func NewFileKey(path string) (Signer, error) {
	return openFileKey(path, true)
}

// OpenFileKey loads an EXISTING ed25519 key and never generates one. The operator commands use it because a
// missing key there means the wrong path (a relative key_path resolved against a different working directory),
// not a new install — and minting a fresh identity in that moment would be actively dangerous: no existing
// anchor would verify under it, so every off-box witness would be silently discarded and a rewritten trail
// would verify clean. An operator inspecting a possible tamper must get an error, not a new key.
func OpenFileKey(path string) (Signer, error) {
	return openFileKey(path, false)
}

func openFileKey(path string, generate bool) (Signer, error) {
	seed, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("sign: read key %s: %w", path, err)
		}
		if !generate {
			return nil, fmt.Errorf("sign: signing key %s does not exist; this command will not create one "+
				"(a relative key_path resolves against the current directory — check that it points at the "+
				"monitor's real key)", path)
		}
		return generateFileKey(path)
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("sign: stat key %s: %w", path, err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		return nil, fmt.Errorf("sign: key %s has mode %#o, want 0600", path, perm)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("sign: key %s is %d bytes, want an ed25519 seed of %d", path, len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return newFileKey(priv), nil
}

func generateFileKey(path string) (Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sign: generate key: %w", err)
	}
	if err := os.WriteFile(path, priv.Seed(), 0o600); err != nil {
		return nil, fmt.Errorf("sign: write key %s: %w", path, err)
	}
	return newFileKey(priv), nil
}

func newFileKey(priv ed25519.PrivateKey) *fileKey {
	pub := priv.Public().(ed25519.PublicKey)
	return &fileKey{
		priv:  priv,
		pub:   pub,
		keyID: "filekey:" + hex.EncodeToString(pub[:8]),
	}
}

func (k *fileKey) Sign(digest []byte) ([]byte, string, error) {
	return ed25519.Sign(k.priv, digest), k.keyID, nil
}

// Verify pins to this key's own id (the dev signer is single-key), so an anchor's self-declared key_id is
// never trusted on its own.
func (k *fileKey) Verify(digest, sig []byte, keyID string) (bool, error) {
	if keyID != k.keyID {
		return false, nil
	}
	return ed25519.Verify(k.pub, digest, sig), nil
}
