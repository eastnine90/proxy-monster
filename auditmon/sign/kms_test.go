package sign

import (
	"bytes"
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// mockKMS records the inputs it receives and returns canned outputs, so the test asserts the request shape
// without any real AWS call.
type mockKMS struct {
	signInput   *kms.SignInput
	verifyInput *kms.VerifyInput
	signature   []byte
	valid       bool
	verifyErr   error
}

func (m *mockKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	m.signInput = in
	return &kms.SignOutput{Signature: m.signature}, nil
}

func (m *mockKMS) Verify(_ context.Context, in *kms.VerifyInput, _ ...func(*kms.Options)) (*kms.VerifyOutput, error) {
	m.verifyInput = in
	if m.verifyErr != nil {
		return nil, m.verifyErr
	}
	return &kms.VerifyOutput{SignatureValid: m.valid}, nil
}

// TestAnchorDigestBindsUpToIDAndHead confirms the signed digest changes when EITHER the anchored id or the
// head hash changes, so a signature can never be re-labeled under a different up_to_id.
func TestAnchorDigestBindsUpToIDAndHead(t *testing.T) {
	head := bytes.Repeat([]byte{0x11}, 32)
	other := bytes.Repeat([]byte{0x22}, 32)

	if bytes.Equal(AnchorDigest(1, head), AnchorDigest(2, head)) {
		t.Fatal("digest must differ when up_to_id differs")
	}
	if bytes.Equal(AnchorDigest(1, head), AnchorDigest(1, other)) {
		t.Fatal("digest must differ when head hash differs")
	}
	if len(AnchorDigest(1, head)) != 32 {
		t.Fatalf("digest length = %d, want 32", len(AnchorDigest(1, head)))
	}
}

func TestKMSSignBuildsDigestRequest(t *testing.T) {
	head := bytes.Repeat([]byte{0xAB}, 32)
	mock := &mockKMS{signature: []byte("sig-bytes"), valid: true}
	signer := NewKMS(mock, "alias/pm-audit-signer")

	sig, keyID, err := signer.Sign(head)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if string(sig) != "sig-bytes" {
		t.Errorf("signature = %q, want sig-bytes", sig)
	}
	if keyID != "alias/pm-audit-signer" {
		t.Errorf("keyID = %q", keyID)
	}
	if mock.signInput == nil {
		t.Fatal("Sign was not called")
	}
	if mock.signInput.KeyId == nil || *mock.signInput.KeyId != "alias/pm-audit-signer" {
		t.Errorf("sign KeyId = %v", mock.signInput.KeyId)
	}
	if mock.signInput.MessageType != types.MessageTypeDigest {
		t.Errorf("sign MessageType = %v, want DIGEST", mock.signInput.MessageType)
	}
	if !bytes.Equal(mock.signInput.Message, head) {
		t.Errorf("sign Message != head hash")
	}
	if mock.signInput.SigningAlgorithm != types.SigningAlgorithmSpecEcdsaSha256 {
		t.Errorf("sign algorithm = %v", mock.signInput.SigningAlgorithm)
	}
}

func TestKMSVerifyPassesThroughValidity(t *testing.T) {
	head := bytes.Repeat([]byte{0xCD}, 32)
	mock := &mockKMS{valid: true}
	// A prior key id is allowlisted for rotation, so an anchor signed under it still verifies.
	signer := NewKMS(mock, "alias/pm-audit-signer", "alias/prev-key")

	ok, err := signer.Verify(head, []byte("sig"), "alias/prev-key")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("expected SignatureValid=true to pass through")
	}
	if mock.verifyInput == nil {
		t.Fatal("Verify was not called")
	}
	// Verify uses the allowlisted key id it was handed (needed so an old anchor verifies under its old key).
	if mock.verifyInput.KeyId == nil || *mock.verifyInput.KeyId != "alias/prev-key" {
		t.Errorf("verify KeyId = %v, want alias/prev-key", mock.verifyInput.KeyId)
	}
	if mock.verifyInput.MessageType != types.MessageTypeDigest {
		t.Errorf("verify MessageType = %v, want DIGEST", mock.verifyInput.MessageType)
	}

	mock.valid = false
	ok, err = signer.Verify(head, []byte("sig"), "alias/prev-key")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("expected SignatureValid=false to pass through")
	}
}

// TestKMSVerifyRejectsUntrustedKeyID is the regression for the pinned-key fix: an anchor's self-declared
// key_id that is not a configured/allowlisted key is refused outright, and KMS is never asked to verify
// under an attacker-chosen key.
func TestKMSVerifyRejectsUntrustedKeyID(t *testing.T) {
	head := bytes.Repeat([]byte{0xCD}, 32)
	mock := &mockKMS{valid: true}
	signer := NewKMS(mock, "alias/pm-audit-signer")

	ok, err := signer.Verify(head, []byte("sig"), "alias/attacker-key")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("expected an untrusted key_id to be rejected (false)")
	}
	if mock.verifyInput != nil {
		t.Fatalf("KMS Verify must not be called for an untrusted key_id, got %+v", mock.verifyInput)
	}
}

// TestKMSVerifyMapsInvalidSignatureException confirms a bad-signature exception from KMS maps to a definitive
// false (a junk anchor is skipped), not an error the monitor would treat as an infrastructure blip.
func TestKMSVerifyMapsInvalidSignatureException(t *testing.T) {
	head := bytes.Repeat([]byte{0xCD}, 32)
	mock := &mockKMS{verifyErr: &types.KMSInvalidSignatureException{}}
	signer := NewKMS(mock, "alias/pm-audit-signer")

	ok, err := signer.Verify(head, []byte("sig"), "alias/pm-audit-signer")
	if err != nil {
		t.Fatalf("expected invalid-signature exception mapped to (false,nil), got err %v", err)
	}
	if ok {
		t.Fatal("expected invalid signature to verify false")
	}
}
