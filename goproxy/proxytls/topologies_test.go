package proxytls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// The deployment topologies proxy-monster supports, each asserted end to end from a certificate file to what
// the proxy advertises and what a client can do with it. Every certificate is generated in-process, so this
// runs anywhere with no fixtures and no network.
//
// The point is that NONE of them is an error. The proxy serves TLS and publishes what it presents; whether a
// client can build a path is the client's verification to perform and report. Refusing to register (or to
// boot) over an incomplete chain would turn one client's TLS error into a datasource that does not exist —
// no catalog, every decision failing closed.
func TestSupportedCertificateTopologies(t *testing.T) {
	root, rootKey := testCA(t, "Topology Root CA", nil, nil)
	inter, interKey := testCA(t, "Topology Intermediate CA", root, rootKey)
	leafPEM, leafKey := testLeaf(t, "proxy.topology.test", inter, interKey)
	selfPEM, selfKey := testSelfSigned(t, "self.topology.test")

	cases := []struct {
		name string
		// what the operator puts in PM_TLS_CERT
		certPEM []byte
		key     []byte
		// how many certificates the proxy should advertise
		wantCerts int
		// Whether the file terminates in a self-signed anchor, i.e. whether an OpenSSL-family client (psql,
		// mysql, DataGrip) can build a complete path from it with no partial-chain flag. This is what
		// bundleShortcoming reports.
		//
		// Deliberately NOT named "usable by every client": pmon loads the whole PEM into a Go root pool, and Go
		// trusts a certificate found DIRECTLY in that pool (crypto/x509 verify.go), so pmon also accepts a bare
		// CA-issued leaf that psql would reject. Asserting one boolean for "the client" would encode a claim
		// that is false for one of the two clients this project ships — see the per-client assertions below.
		wantUsableAlone bool
	}{
		{
			name:            "self-signed leaf — its own anchor",
			certPEM:         selfPEM,
			key:             selfKey,
			wantCerts:       1,
			wantUsableAlone: true,
		},
		{
			name:            "full chain — leaf + intermediate + root",
			certPEM:         concat(leafPEM, pemCert(inter.Raw), pemCert(root.Raw)),
			key:             leafKey,
			wantCerts:       3,
			wantUsableAlone: true,
		},
		{
			name:            "leaf only — no anchor for an OpenSSL-family client",
			certPEM:         leafPEM,
			key:             leafKey,
			wantCerts:       1,
			wantUsableAlone: false,
		},
		{
			name:            "leaf + intermediate — stops short of the root",
			certPEM:         concat(leafPEM, pemCert(inter.Raw)),
			key:             leafKey,
			wantCerts:       2,
			wantUsableAlone: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			write(t, dir+"/cert.pem", tc.certPEM)
			write(t, dir+"/key.pem", tc.key)
			r := NewReloading(dir+"/cert.pem", dir+"/key.pem")

			chain, err := r.TrustChain()
			if err != nil {
				t.Fatalf("no topology may be an error — the client verifies, not us: %v", err)
			}
			if n := strings.Count(chain, "BEGIN CERTIFICATE"); n != tc.wantCerts {
				t.Errorf("advertised %d certificates, want %d", n, tc.wantCerts)
			}

			certs := decodeChain(t, chain)
			shortcoming := bundleShortcoming(certs)
			if tc.wantUsableAlone && shortcoming != "" {
				t.Errorf("expected a self-terminating anchor bundle, got shortcoming: %s", shortcoming)
			}
			if !tc.wantUsableAlone && shortcoming == "" {
				t.Error("expected this file to be reported as not self-terminating, but nothing was reported")
			}

			// What a Go client (pmon) actually does with these bytes, asserted rather than assumed. It loads the
			// whole PEM as its root pool, and Go trusts a certificate found directly in that pool — so EVERY
			// topology here verifies for pmon, including the two an OpenSSL-family client rejects. bundleShortcoming
			// is advice for the operator about psql/mysql, NOT a prediction about pmon.
			if err := verifiesAsGoRootPool(certs); err != nil {
				t.Errorf("pmon loads the advertised chain as its root pool, so this topology must verify for it "+
					"(bundleShortcoming describes OpenSSL-family clients, not this one): %v", err)
			}

			// None of these private-PKI certificates is publicly trusted, so a client with only its system
			// store cannot verify them — which is exactly why the chain is published.
			if publiclyTrusted(certs) {
				t.Error("a locally-generated certificate must not appear publicly trusted")
			}
		})
	}
}

// Case 1 (no TLS) is a configuration state rather than a certificate topology: with PM_TLS_CERT unset the
// proxy never builds a TLS config, so there is nothing to advertise and clients connect in plaintext.
func TestNoTLSAdvertisesNothing(t *testing.T) {
	if _, err := NewReloading("", "").TrustChain(); err == nil {
		t.Error("with no certificate configured there is nothing to advertise; TrustChain must say so")
	}
}

// ---- helpers: real certificates, built in-process ----

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// verifiesAsGoRootPool mirrors what pmon's upstreamTLSConfig does: every certificate in the advertised PEM
// goes into the root pool, then the leaf is verified against it. Kept as a local mirror rather than importing
// pmon (a separate module) — the shape being asserted is Go's crypto/x509 behavior, not pmon's code.
func verifiesAsGoRootPool(certs []*x509.Certificate) error {
	roots := x509.NewCertPool()
	for _, c := range certs {
		roots.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, DNSName: certs[0].DNSNames[0]})
	return err
}

func decodeChain(t *testing.T, chainPEM string) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	rest := []byte(chainPEM)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		t.Fatal("no certificates decoded")
	}
	return out
}

// testCA builds a CA certificate; pass a nil parent for a self-signed root.
func testCA(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return c, key
}

func testLeaf(t *testing.T, cn string, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	return pemCert(der), marshalKey(t, key)
}

func testSelfSigned(t *testing.T, cn string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// A self-signed server certificate in the wild is often CA:FALSE, and it still anchors itself.
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create self-signed: %v", err)
	}
	return pemCert(der), marshalKey(t, key)
}

func marshalKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	return n
}

// The advertised address has to be covered by the certificate, because a client using verify-full checks the
// exact host it dialed. Advertising a bare IP against a DNS-only certificate is the common way to get this
// wrong, and it fails for EVERY client — so the proxy reports it at boot instead of leaving each operator to
// discover it from a psql error.
func TestAdvertisedAddressMustBeCoveredByTheCertificate(t *testing.T) {
	dir := t.TempDir()
	dnsPEM, dnsKey := testSelfSigned(t, "proxy.covered.test")
	write(t, dir+"/dns.pem", dnsPEM)
	write(t, dir+"/dns.key", dnsKey)
	dns := NewReloading(dir+"/dns.pem", dir+"/dns.key")

	ipPEM, ipKey := testSelfSignedIP(t, "10.20.30.40")
	write(t, dir+"/ip.pem", ipPEM)
	write(t, dir+"/ip.key", ipKey)
	ip := NewReloading(dir+"/ip.pem", dir+"/ip.key")

	cases := []struct {
		name       string
		r          *Reloading
		addr       string
		wantReason bool
	}{
		{"hostname the cert covers", dns, "proxy.covered.test:6033", false},
		{"hostname with no port", dns, "proxy.covered.test", false},
		{"a different hostname", dns, "other.host.test:6033", true},
		{"a bare IP against a DNS-only cert", dns, "10.20.30.40:6033", true},
		{"an IP the cert carries as an IP SAN", ip, "10.20.30.40:6033", false},
		{"a hostname against an IP-only cert", ip, "proxy.covered.test:6033", true},
		{"a bracketed IPv6 literal", dns, "[2001:db8::1]:6033", true},
		{"no advertised address at all", dns, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, err := tc.r.AddressShortcoming(tc.addr)
			if err != nil {
				t.Fatalf("AddressShortcoming: %v", err)
			}
			if tc.wantReason && reason == "" {
				t.Errorf("expected a mismatch to be reported for %q", tc.addr)
			}
			if !tc.wantReason && reason != "" {
				t.Errorf("expected %q to be accepted, got: %s", tc.addr, reason)
			}
		})
	}
}

// TestHostOnlyExtractsTheHost pins hostOnly's OUTPUT, not just the pass/fail of the check above it.
//
// AddressShortcoming only reports whether SOME reason came back, so it cannot distinguish a correctly-parsed
// host from a mangled one — both produce a mismatch for an address the certificate does not cover. A naive
// `LastIndex(":")` port strip passes every case in that table while returning "[2001:db8::1]" (brackets left
// on, so VerifyHostname and net.ParseIP both fail to recognize it) and truncating a bare IPv6 literal
// "2001:db8::1" to "2001:db8:". Asserting the extracted string is what makes those visible.
func TestHostOnlyExtractsTheHost(t *testing.T) {
	cases := []struct{ addr, want string }{
		{"proxy.covered.test", "proxy.covered.test"},
		{"proxy.covered.test:6033", "proxy.covered.test"},
		{"10.0.0.1:6033", "10.0.0.1"},
		{"10.0.0.1", "10.0.0.1"},
		// The bracket forms are the ones a naive split gets wrong.
		{"[2001:db8::1]:6033", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		// A bare IPv6 literal carries colons but no port; truncating at the last one corrupts the address.
		{"2001:db8::1", "2001:db8::1"},
		{"", ""},
		{"   ", ""},
	}
	for _, tc := range cases {
		if got := hostOnly(tc.addr); got != tc.want {
			t.Errorf("hostOnly(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
	// And the extracted host must be recognizable AS an address, which is what the IP-SAN branch of
	// AddressShortcoming depends on: a bracketed leftover parses as nil and would be misreported as a hostname.
	if net.ParseIP(hostOnly("[2001:db8::1]:6033")) == nil {
		t.Error("an extracted IPv6 literal must parse as an IP, or the IP-SAN diagnosis silently misfires")
	}
}

// An expired certificate is advertised like any other: every client rejects it with a precise message, and
// withholding it would leave an operator with no way to see what the proxy is presenting. This pins that the
// proxy does not silently swallow the case — it is a known diagnosis gap, not a refusal.
func TestAnExpiredCertificateIsStillAdvertised(t *testing.T) {
	dir := t.TempDir()
	certPEM, key := testSelfSignedExpired(t, "expired.topology.test")
	write(t, dir+"/cert.pem", certPEM)
	write(t, dir+"/key.pem", key)
	chain, err := NewReloading(dir+"/cert.pem", dir+"/key.pem").TrustChain()
	if err != nil {
		t.Fatalf("an expired certificate must still be advertised, not refused: %v", err)
	}
	if strings.Count(chain, "BEGIN CERTIFICATE") != 1 {
		t.Error("expected the expired certificate to be advertised")
	}
}

func testSelfSignedIP(t *testing.T, ip string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: ip},
		IPAddresses:           []net.IP{net.ParseIP(ip)},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return pemCert(der), marshalKey(t, key)
}

func testSelfSignedExpired(t *testing.T, cn string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{cn},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return pemCert(der), marshalKey(t, key)
}
