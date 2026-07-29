// Package proxytls builds the proxy's client-facing TLS config from a cert + key on disk, reloading it
// when the files change (an ACME issuer renews the ~90-day Let's Encrypt leaf in place), so a
// long-running proxy picks up the new cert without a restart.
//
// Go's stdlib tls.LoadX509KeyPair natively parses SEC1 "EC PRIVATE KEY", PKCS1, and PKCS8 PEM, so this
// package needs zero extra dependencies.
package proxytls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// build parses the cert/key pair at certPath/keyPath into a server-side *tls.Config.
func build(certPath, keyPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("proxytls: loading key pair (%s, %s): %w", certPath, keyPath, err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// Reloading rebuilds the *tls.Config when the cert/key files change on disk. Current is called per
// connection; the mtime check is a cheap stat, and the config is only re-parsed when a file actually
// changed.
type Reloading struct {
	certPath, keyPath string

	mu        sync.Mutex
	cached    *tls.Config
	certMtime time.Time
	keyMtime  time.Time
}

// NewReloading creates a Reloading TLS config provider for the given cert/key paths. It does not read
// the files until the first Current() call.
func NewReloading(certPath, keyPath string) *Reloading {
	return &Reloading{certPath: certPath, keyPath: keyPath}
}

// Current returns the current *tls.Config, rebuilding it if either file's mtime changed (or this is the
// first call). A failed rebuild leaves the prior cache + mtimes untouched, so the next call retries.
func (r *Reloading) Current() (*tls.Config, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	certStat, err := os.Stat(r.certPath)
	if err != nil {
		return r.rebuildLocked()
	}
	keyStat, err := os.Stat(r.keyPath)
	if err != nil {
		return r.rebuildLocked()
	}

	if r.cached == nil || !certStat.ModTime().Equal(r.certMtime) || !keyStat.ModTime().Equal(r.keyMtime) {
		cfg, err := build(r.certPath, r.keyPath)
		if err != nil {
			return nil, err
		}
		r.cached = cfg
		r.certMtime = certStat.ModTime()
		r.keyMtime = keyStat.ModTime()
	}
	return r.cached, nil
}

// TrustChain returns the certificate chain a client may use to trust this proxy: PEM, leaf first, exactly as
// the cert file carries it. Always advertised, whatever the topology — a leaf certificate and its issuers are
// public material the proxy already presents to every TLS client, and the control plane is the natural place
// to distribute it from.
//
// What a client DOES with it differs, and that is the client's call, not ours:
//   - self-signed leaf  -> the leaf is the anchor; use it as the root pool
//   - private CA        -> leaf + intermediates + root; use it as the root pool
//   - public CA (ACME)  -> the client already holds the root, so it may ignore this entirely and verify
//     against its system trust store. The chain is still worth having: it is what the proxy presents, and an
//     operator can inspect or pin it.
//
// [publiclyTrusted] reports whether a client could verify without any of this, so callers can say so; and
// [bundleShortcoming] reports why the file may not work as a standalone anchor bundle. Both are advisory.
// Nothing here refuses: a chain withheld leaves an operator with nothing to install and no way to see why,
// while a chain a client cannot use produces a precise error from the client itself.
//
// The private key is never touched.
func (r *Reloading) TrustChain() (string, error) {
	certs, ders, err := r.chain()
	if err != nil {
		return "", err
	}
	if reason := bundleShortcoming(certs); reason != "" && !publiclyTrusted(certs) {
		slog.Warn("the wire cert chain may not work as a client trust anchor; advertising it anyway",
			"cert", r.certPath, "reason", reason)
	}
	return pemChain(ders)
}

// PubliclyTrusted reports whether the leaf verifies against the system trust store using the intermediates
// the file carries — i.e. whether a client needs the advertised chain at all.
func (r *Reloading) PubliclyTrusted() (bool, error) {
	certs, _, err := r.chain()
	if err != nil {
		return false, err
	}
	return publiclyTrusted(certs), nil
}

// chain parses the currently-loaded certificate file, returning both the parsed certs and their DER.
func (r *Reloading) chain() ([]*x509.Certificate, [][]byte, error) {
	cfg, err := r.Current()
	if err != nil {
		return nil, nil, err
	}
	if len(cfg.Certificates) == 0 || len(cfg.Certificates[0].Certificate) == 0 {
		return nil, nil, fmt.Errorf("proxytls: no leaf certificate loaded")
	}
	ders := cfg.Certificates[0].Certificate
	certs := make([]*x509.Certificate, 0, len(ders))
	for i, der := range ders {
		c, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("proxytls: parsing certificate %d of the chain: %w", i, parseErr)
		}
		certs = append(certs, c)
	}
	return certs, ders, nil
}

// publiclyTrusted reports whether the leaf chains to the system trust store, offering the rest of the file as
// intermediates — exactly what the proxy presents on the wire.
func publiclyTrusted(certs []*x509.Certificate) bool {
	mids := x509.NewCertPool()
	for _, c := range certs[1:] {
		mids.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{Intermediates: mids})
	return err == nil
}

// AddressShortcoming reports why the loaded leaf may not satisfy a client dialing advertiseAddr, or "" when
// it looks fine. A client using verify-full (the default this project recommends) checks the certificate
// covers the exact host it dialed, so a proxy advertising a name or IP the certificate does not carry fails
// for every client — the most common form being an advertised bare IP against a DNS-only certificate.
//
// Advisory, like everything else here: it is logged, never enforced. The address and the certificate are both
// the operator's to choose, and the client produces the authoritative error.
func (r *Reloading) AddressShortcoming(advertiseAddr string) (string, error) {
	certs, _, err := r.chain()
	if err != nil {
		return "", err
	}
	host := hostOnly(advertiseAddr)
	if host == "" {
		return "", nil
	}
	if err := certs[0].VerifyHostname(host); err != nil {
		if ip := net.ParseIP(host); ip != nil && len(certs[0].IPAddresses) == 0 {
			return fmt.Sprintf(
				"the advertised address %s is an IP but the certificate carries no IP SAN (only %v), so a client "+
					"using verify-full will reject it; advertise a hostname the certificate covers, or reissue "+
					"the certificate with an IP SAN", host, certs[0].DNSNames), nil
		}
		return fmt.Sprintf(
			"the certificate does not cover the advertised address %s (it covers %v), so a client using "+
				"verify-full will reject it", host, certs[0].DNSNames), nil
	}
	return "", nil
}

// hostOnly strips a :port from an advertised address, leaving an IPv6 literal intact. A bare host with no
// port, and a bracketed IPv6 literal, both have to survive.
func hostOnly(addr string) string {
	a := strings.TrimSpace(addr)
	if a == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(a); err == nil {
		return h
	}
	return strings.Trim(a, "[]")
}

// bundleShortcoming reports why a not-publicly-trusted file may fail as a client's anchor bundle, or "" when
// it looks usable. Advisory only — every caller advertises the chain regardless.
func bundleShortcoming(certs []*x509.Certificate) string {
	leaf, anchor := certs[0], certs[len(certs)-1]
	// The file can only anchor itself if its LAST certificate is self-signed. Checked by signature under its
	// own key rather than by CheckSignatureFrom (which also enforces CA-signing constraints and so would
	// reject an ordinary self-signed CA:FALSE server certificate) and rather than by putting it in a Roots
	// pool (Go trusts whatever is in that pool, so any terminal certificate would pass).
	if err := anchor.CheckSignature(anchor.SignatureAlgorithm, anchor.RawTBSCertificate, anchor.Signature); err != nil {
		if len(certs) == 1 {
			return "it carries one certificate that is not self-signed, so a client has no anchor for it; " +
				"append the issuing CA, or rely on the client's own trust store"
		}
		return "the chain stops at an intermediate rather than a self-signed anchor, so a client cannot " +
			"terminate the path from this file alone; append the root, or rely on the client's own trust store"
	}
	if len(certs) == 1 {
		return ""
	}
	// A self-signed terminal certificate IS an anchor, so the remaining question is whether the leaf actually
	// chains to it through the intermediates present.
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	mids := x509.NewCertPool()
	for _, c := range certs[1 : len(certs)-1] {
		mids.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: mids}); err != nil {
		return "the leaf does not chain to the self-signed certificate at the end of the file: " + err.Error()
	}
	return ""
}

// pemChain re-encodes DER certificates as PEM, leaf first — the order TLS uses and clients expect.
func pemChain(ders [][]byte) (string, error) {
	var b strings.Builder
	for _, der := range ders {
		if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return "", fmt.Errorf("proxytls: re-encoding the chain: %w", err)
		}
	}
	return b.String(), nil
}

// rebuildLocked attempts a rebuild when stat'ing a file failed (e.g. it was momentarily missing during a
// rotation); its error, if any, is returned to the caller without disturbing the cache.
func (r *Reloading) rebuildLocked() (*tls.Config, error) {
	cfg, err := build(r.certPath, r.keyPath)
	if err != nil {
		return nil, err
	}
	r.cached = cfg
	if st, statErr := os.Stat(r.certPath); statErr == nil {
		r.certMtime = st.ModTime()
	}
	if st, statErr := os.Stat(r.keyPath); statErr == nil {
		r.keyMtime = st.ModTime()
	}
	return r.cached, nil
}
