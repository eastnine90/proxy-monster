package proxytls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testdata(name string) string {
	return filepath.Join("testdata", name)
}

// TestBuildsServerContextFromSEC1ECPrivateKey verifies the SEC1 "EC PRIVATE KEY" leaf format that ACME
// issuers emit builds a server *tls.Config.
func TestBuildsServerContextFromSEC1ECPrivateKey(t *testing.T) {
	cfg, err := build(testdata("ec.crt"), testdata("ec-sec1.key"))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if cfg == nil {
		t.Fatal("build returned a nil *tls.Config")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates = %d, want 1", len(cfg.Certificates))
	}
}

// TestBuildsServerContextFromPKCS8Key verifies a PKCS8 key builds a server *tls.Config.
func TestBuildsServerContextFromPKCS8Key(t *testing.T) {
	cfg, err := build(testdata("ec.crt"), testdata("ec-pkcs8.key"))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if cfg == nil {
		t.Fatal("build returned a nil *tls.Config")
	}
}

// TestGarbageKeyFailsLoudly verifies build() returns an error rather than a usable config for a non-PEM key.
func TestGarbageKeyFailsLoudly(t *testing.T) {
	junk := filepath.Join(t.TempDir(), "pm-junk.key")
	if err := os.WriteFile(junk, []byte("not a pem\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := build(testdata("ec.crt"), junk); err == nil {
		t.Fatal("build() with a garbage key = nil error, want error")
	}
}

// TestReloadingRebuildsOnlyWhenTheFileChanges verifies unchanged files return the same cached *tls.Config
// while a changed key (mtime bumped) rebuilds.
func TestReloadingRebuildsOnlyWhenTheFileChanges(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ec.crt")
	keyPath := filepath.Join(dir, "ec-sec1.key")
	copyFile(t, testdata("ec.crt"), certPath)
	copyFile(t, testdata("ec-sec1.key"), keyPath)

	r := NewReloading(certPath, keyPath)
	a, err := r.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	b, err := r.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if a != b {
		t.Fatal("expected the cached config to be reused when files are unchanged")
	}

	// Rewrite the key file and bump its mtime forward so the reload is unambiguously detected regardless
	// of filesystem mtime resolution.
	copyFile(t, testdata("ec-sec1.key"), keyPath)
	future := time.Now().Add(1 * time.Hour)
	if err := os.Chtimes(keyPath, future, future); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	c, err := r.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if c == a {
		t.Fatal("expected a rebuilt config (different pointer) after the key file changed")
	}
}

// TestCurrentSurfacesStatErrorWhenFilesAreMissing exercises the "stat error -> attempt rebuild and
// surface its error" path (build() itself will fail since the files don't exist).
func TestCurrentSurfacesStatErrorWhenFilesAreMissing(t *testing.T) {
	r := NewReloading(filepath.Join(t.TempDir(), "missing.crt"), filepath.Join(t.TempDir(), "missing.key"))
	if _, err := r.Current(); err == nil {
		t.Fatal("Current() with missing files = nil error, want error")
	}
}

// TestTrustChainIsTheCertsTheProxyServes pins the producer/consumer contract: the advertised chain must be
// exactly the certificates the proxy presents on the wire, leaf first, because every client verifies against
// it — pmon as its root pool, psql/mysql/DataGrip as sslrootcert. Decoded here independently of
// TrustChain's own tls.LoadX509KeyPair path, so a divergence between the two would fail this test.
func TestTrustChainIsTheCertsTheProxyServes(t *testing.T) {
	pemBytes, err := os.ReadFile(testdata("ec.crt"))
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("first PEM block is not a CERTIFICATE: %+v", block)
	}

	chain, err := NewReloading(testdata("ec.crt"), testdata("ec-sec1.key")).TrustChain()
	if err != nil {
		t.Fatalf("TrustChain: %v", err)
	}
	got, _ := pem.Decode([]byte(chain))
	if got == nil {
		t.Fatalf("TrustChain returned no parseable PEM: %q", chain)
	}
	if !bytes.Equal(got.Bytes, block.Bytes) {
		t.Errorf("the advertised leaf is not the certificate the proxy serves")
	}
	// A self-signed cert is its own anchor, so its chain is exactly one block. More would mean the encoder
	// emitted something the file does not carry.
	if n := strings.Count(chain, "BEGIN CERTIFICATE"); n != 1 {
		t.Errorf("chain has %d certificates, want 1 for a self-signed leaf", n)
	}
}

// TestPubliclyTrustedIsReportedNotWithheld: a publicly-trusted leaf still gets advertised — the chain is
// public material, and an operator may want to inspect or distribute exactly what the proxy presents.
// PubliclyTrusted() reports that a client does not NEED it, which is what the boot log states and what
// PM_TLS_NO_ADVERTISE lets an operator act on. Opt-in — see the env vars below.
func TestPubliclyTrustedIsReportedNotWithheld(t *testing.T) {
	// A publicly-trusted certificate cannot be minted in a test, so this one is opt-in: point
	// PM_TEST_PUBLIC_CERT / PM_TEST_PUBLIC_KEY at a real publicly-trusted pair (a Let's Encrypt
	// leaf and its key) to exercise the path. Unset, the case skips.
	cert, key := os.Getenv("PM_TEST_PUBLIC_CERT"), os.Getenv("PM_TEST_PUBLIC_KEY")
	if cert == "" || key == "" {
		t.Skip("set PM_TEST_PUBLIC_CERT and PM_TEST_PUBLIC_KEY to a publicly-trusted pair to run this")
	}
	for _, f := range []string{cert, key} {
		if _, err := os.Stat(f); err != nil {
			t.Skipf("no publicly-trusted cert available at %s", f)
		}
	}
	r := NewReloading(cert, key)
	public, err := r.PubliclyTrusted()
	if err != nil {
		t.Fatalf("PubliclyTrusted: %v", err)
	}
	if !public {
		t.Skip("the certificate on this machine is not publicly trusted; nothing to assert")
	}
	chain, err := r.TrustChain()
	if err != nil {
		t.Fatalf("a publicly-trusted cert must still be advertised: %v", err)
	}
	if strings.Count(chain, "BEGIN CERTIFICATE") == 0 {
		t.Error("the chain must still be advertised — withholding it leaves an operator nothing to inspect")
	}
}

// TestTrustChainAdvertisesEvenAQuestionableBundle: a cert file that cannot serve as a client's anchor is
// still advertised, with a warning. Refusing would stop the proxy registering at all — no datasource, no
// catalog, every decision failing closed — to prevent one client's TLS error. The client verifies and is the
// only party that can report a meaningful reason, so the proxy hands over what it has and says why it looks
// wrong.
func TestTrustChainAdvertisesEvenAQuestionableBundle(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := selfSignedCA(t)
	leafPEM, leafKeyPEM := leafSignedBy(t, caCert, caKey)

	// Leaf alone: no anchor in the file, and not publicly trusted.
	writeFile(t, dir+"/leaf.crt", leafPEM)
	writeFile(t, dir+"/leaf.key", leafKeyPEM)
	chain, err := NewReloading(dir+"/leaf.crt", dir+"/leaf.key").TrustChain()
	if err != nil {
		t.Fatalf("an unusable-looking bundle must still be advertised, not refused: %v", err)
	}
	if n := strings.Count(chain, "BEGIN CERTIFICATE"); n != 1 {
		t.Errorf("chain has %d certificates, want the 1 the file carries", n)
	}
	// bundleShortcoming is what the warning is built from, so assert the diagnosis rather than the log line.
	certs := parseChain(t, chain)
	if reason := bundleShortcoming(certs); reason == "" {
		t.Error("a leaf with no anchor must be reported as questionable, even though it is advertised")
	}

	// Same leaf WITH its issuer: a real bundle, and nothing to report.
	writeFile(t, dir+"/full.crt", append(append([]byte{}, leafPEM...), pemEncodeCert(caCert.Raw)...))
	full, err := NewReloading(dir+"/full.crt", dir+"/leaf.key").TrustChain()
	if err != nil {
		t.Fatalf("a leaf plus its issuer must advertise cleanly: %v", err)
	}
	if n := strings.Count(full, "BEGIN CERTIFICATE"); n != 2 {
		t.Errorf("chain has %d certificates, want 2 (leaf + issuer)", n)
	}
	if reason := bundleShortcoming(parseChain(t, full)); reason != "" {
		t.Errorf("a leaf plus its issuer must have nothing to report, got: %s", reason)
	}
}

// parseChain decodes a PEM chain back to certificates, so a test can assert on the diagnosis the warning
// carries instead of scraping log output.
func parseChain(t *testing.T, chainPEM string) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	rest := []byte(chainPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		t.Fatal("no certificates in the chain")
	}
	return out
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", src, err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatalf("WriteFile(%s): %v", dst, err)
	}
}

// ---- helpers: build real certificates in-process, so the tests need no fixture files or openssl ----

func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func selfSignedCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return cert, key
}

func leafSignedBy(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "pm-proxy.example.com"},
		DNSNames:     []string{"pm-proxy.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	return pemEncodeCert(der), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
