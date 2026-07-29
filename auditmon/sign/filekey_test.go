package sign

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileKeyGeneratesAndRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")

	signer, err := NewFileKey(path)
	if err != nil {
		t.Fatalf("new file key: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat generated key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("generated key mode = %#o, want 0600", perm)
	}

	head := []byte("0123456789abcdef0123456789abcdef") // 32-byte stand-in head hash
	sig, keyID, err := signer.Sign(head)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ok, err := signer.Verify(head, sig, keyID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("valid signature failed to verify")
	}
}

func TestFileKeyReloadsExistingKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")

	first, err := NewFileKey(path)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	head := []byte("0123456789abcdef0123456789abcdef")
	sig, keyID, err := first.Sign(head)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Reloading the same file yields the same key, so a signature from the first load still verifies.
	second, err := NewFileKey(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	ok, err := second.Verify(head, sig, keyID)
	if err != nil {
		t.Fatalf("verify after reload: %v", err)
	}
	if !ok {
		t.Fatal("reloaded key failed to verify a prior signature")
	}
}

func TestFileKeyRejectsTamperedSignature(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	signer, err := NewFileKey(path)
	if err != nil {
		t.Fatalf("new file key: %v", err)
	}
	head := []byte("0123456789abcdef0123456789abcdef")
	sig, keyID, err := signer.Sign(head)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig[0] ^= 0xFF
	ok, err := signer.Verify(head, sig, keyID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("tampered signature verified true")
	}
}

func TestFileKeyRejectsBadPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if _, err := NewFileKey(path); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := NewFileKey(path); err == nil {
		t.Fatal("expected an error loading a world-readable key, got nil")
	}
}
