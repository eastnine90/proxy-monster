package sign

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSAPI is the subset of the KMS client this package uses (so tests inject a mock). The real *kms.Client
// satisfies it.
type KMSAPI interface {
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error)
}

// The signed message is a 32-byte SHA-256 digest, so it is signed as a DIGEST message under ECDSA_SHA_256.
// See auditmon/README.md for the signing-algorithm tradeoffs.
const signingAlgorithm = types.SigningAlgorithmSpecEcdsaSha256

type kmsSigner struct {
	client KMSAPI
	keyID  string
	// allowedKeyIDs is the set of key ids verification will trust — the active signing key plus any prior
	// keys still valid for rotation. An anchor's own key_id field is checked against this set and never
	// trusted on its own, so a forged anchor cannot point verification at a key the attacker controls.
	allowedKeyIDs map[string]struct{}
}

// NewKMS wraps a KMS client bound to a signing key. Additional allowedKeyIDs are prior keys still trusted
// for verification during rotation; the active keyID is always trusted. Verification against any key
// outside this set is refused.
func NewKMS(client KMSAPI, keyID string, allowedKeyIDs ...string) Signer {
	allowed := map[string]struct{}{keyID: {}}
	for _, k := range allowedKeyIDs {
		if k != "" {
			allowed[k] = struct{}{}
		}
	}
	return &kmsSigner{client: client, keyID: keyID, allowedKeyIDs: allowed}
}

func (s *kmsSigner) Sign(digest []byte) ([]byte, string, error) {
	out, err := s.client.Sign(context.Background(), &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: signingAlgorithm,
	})
	if err != nil {
		return nil, "", err
	}
	return out.Signature, s.keyID, nil
}

func (s *kmsSigner) Verify(digest, sig []byte, keyID string) (bool, error) {
	// Pin verification to a configured key. An anchor's self-declared key_id is attacker-controllable, so a
	// key outside the allowlist is a definitive non-verification (false), not an error to retry.
	if _, ok := s.allowedKeyIDs[keyID]; !ok {
		return false, nil
	}
	out, err := s.client.Verify(context.Background(), &kms.VerifyInput{
		KeyId:            aws.String(keyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		Signature:        sig,
		SigningAlgorithm: signingAlgorithm,
	})
	if err != nil {
		// KMS reports a bad signature as an error, not SignatureValid=false. Map it to a definitive false so
		// a single junk anchor object is skipped rather than treated as an infrastructure failure to retry.
		var invalid *types.KMSInvalidSignatureException
		if errors.As(err, &invalid) {
			return false, nil
		}
		return false, err
	}
	return out.SignatureValid, nil
}
