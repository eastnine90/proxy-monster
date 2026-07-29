package daemon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

// TestLocalServerGreetDoesNotAdvertiseConnectWithDB guards a cross-module regression: pmon's broker
// greeting must not advertise CONNECT_WITH_DB. pmon reads the local client's handshake but never forwards
// a handshake-selected database upstream, so advertising the capability would let a pmon client whose DSN
// selects a non-default database silently operate on the wrong one.
func TestLocalServerGreetDoesNotAdvertiseConnectWithDB(t *testing.T) {
	clientSide, brokerSide := net.Pipe()
	defer clientSide.Close()
	defer brokerSide.Close()

	type greetResult struct {
		caps uint32
		err  error
	}
	done := make(chan greetResult, 1)
	go func() {
		caps, err := localServerGreet(brokerSide, make([]byte, 20))
		done <- greetResult{caps: caps, err: err}
	}()

	_, greeting, err := mysqlwire.ReadPacket(clientSide)
	if err != nil {
		t.Fatalf("read broker greeting: %v", err)
	}
	parsed, err := mysqlwire.ParseHandshakeV10(greeting)
	if err != nil {
		t.Fatalf("parse broker greeting: %v", err)
	}
	if parsed.Capabilities&mysqlwire.CapConnectWithDB != 0 {
		t.Fatalf("pmon greeting caps = %#x advertise CONNECT_WITH_DB; a client's DSN database would be silently dropped", parsed.Capabilities)
	}

	// Unblock localServerGreet with a minimal handshake response (it reads only the leading capability flags).
	if err := mysqlwire.WritePacket(clientSide, 1, make([]byte, 32)); err != nil {
		t.Fatalf("write client handshake response: %v", err)
	}
	if res := <-done; res.err != nil {
		t.Fatalf("localServerGreet: %v", res.err)
	}
}

// selfSignedServer builds a server TLS config with a fresh self-signed leaf and returns it alongside the
// leaf DER — the exact bytes a client receives as rawCerts[0] and the proxy would advertise as its SHA-256
// Self-signed on purpose: it is its own trust anchor, which is the ordinary proxy case.
func selfSignedServer(t *testing.T) (*tls.Config, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "proxy.example"},
		// A DNS SAN is required now that verification checks the hostname — the pin it replaced did not.
		DNSNames:              []string{"proxy.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}
	return cfg, der
}

// tlsHandshake drives a real client↔server TLS handshake over an in-memory pipe and returns the CLIENT's
// result — so verification is exercised through the actual handshake against the real certificate, not by
// calling a callback with pretend bytes.
//
// Both ends are closed before waiting on the server. net.Pipe is unbuffered and synchronous, so a client
// that ABORTS mid-handshake (which is exactly what a verification failure does) leaves the server blocked
// writing a record nobody will read; waiting on it first would hang the test rather than fail it.
func tlsHandshake(t *testing.T, serverCfg, clientCfg *tls.Config) error {
	t.Helper()
	cConn, sConn := net.Pipe()
	// A deadline on the pipe, not just a Close: net.Pipe is synchronous, so a server mid-write when the client
	// aborts stays blocked inside Handshake even after both ends are closed. The deadline makes that write fail
	// instead, which is the only way this returns rather than hanging the suite. A successful handshake takes
	// microseconds, so this only ever elapses on the abort paths the failure cases deliberately exercise.
	deadline := time.Now().Add(2 * time.Second)
	_ = cConn.SetDeadline(deadline)
	_ = sConn.SetDeadline(deadline)
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		_ = tls.Server(sConn, serverCfg).Handshake()
	}()
	err := tls.Client(cConn, clientCfg).Handshake()
	cConn.Close()
	sConn.Close()
	<-srvDone
	return err
}

// TestUpstreamTLSVerifiesAgainstTheAdvertisedChain proves the end-to-end contract through a real handshake:
// a client given the chain the control plane advertised completes the handshake WITH the hostname checked,
// and a chain for a different certificate aborts it before the connection is usable.
//
// The hostname check is the part the leaf-fingerprint pin this replaced could not do: pinning had to set
// InsecureSkipVerify, so a stolen leaf replayed under any name satisfied it. Here a wrong name fails even
// when the certificate itself is the right one.
func TestUpstreamTLSVerifiesAgainstTheAdvertisedChain(t *testing.T) {
	serverCfg, leafDER := selfSignedServer(t)
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))

	cfg, err := upstreamTLSConfig("proxy.example", chain)
	if err != nil {
		t.Fatalf("upstreamTLSConfig: %v", err)
	}
	if err := tlsHandshake(t, serverCfg, cfg); err != nil {
		t.Errorf("handshake against the advertised chain failed: %v", err)
	}

	// A chain for some OTHER certificate must not verify this server.
	_, otherDER := selfSignedServer(t)
	otherChain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherDER}))
	wrongCfg, err := upstreamTLSConfig("proxy.example", otherChain)
	if err != nil {
		t.Fatalf("upstreamTLSConfig: %v", err)
	}
	if err := tlsHandshake(t, serverCfg, wrongCfg); err == nil {
		t.Error("handshake succeeded against a chain for a different certificate — verification is not enforced")
	}

	// The right certificate under the WRONG NAME must also fail. This is what pinning could not catch.
	nameCfg, err := upstreamTLSConfig("someone-else.example", chain)
	if err != nil {
		t.Fatalf("upstreamTLSConfig: %v", err)
	}
	if err := tlsHandshake(t, serverCfg, nameCfg); err == nil {
		t.Error("handshake succeeded with a mismatched server name — the hostname is not being checked")
	}
}

// TestUpstreamTLSRejectsAnUnusableChain: a chain that carries no certificate is a configuration error, and
// must surface as one rather than silently falling back to system trust (which would accept a public CA's
// certificate for this host — not what the control plane advertised).
func TestUpstreamTLSRejectsAnUnusableChain(t *testing.T) {
	if _, err := upstreamTLSConfig("proxy.example", "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"); err == nil {
		t.Error("an unparseable chain must be an error, not a silent fallback to system trust")
	}
}

// TestProxyConnectRefusesPlaintextWhenTLSIsExpected proves the downgrade refusal end-to-end, and proves it is
// driven by the TLS REQUIREMENT rather than by the presence of trust material.
//
// The second case is the one that matters. A proxy serving a publicly-trusted certificate publishes NO chain
// (PM_TLS_NO_ADVERTISE), so a refusal gated on "is a chain advertised" would go dead for exactly that
// deployment: an on-path attacker answers the unauthenticated greeting without CLIENT_SSL and pmon hands over
// a live session token in plaintext. Gating on wireTLS closes it. If someone reintroduces the chain-based
// gate, the noChain subtest fails.
func TestProxyConnectRefusesPlaintextWhenTLSIsExpected(t *testing.T) {
	const chain = "-----BEGIN CERTIFICATE-----\nirrelevant\n-----END CERTIFICATE-----\n"
	cases := []struct {
		name  string
		chain string
	}{
		{name: "a chain is advertised", chain: chain},
		// No trust material at all: only wireTLS says TLS is expected.
		{name: "no chain is published, only the TLS requirement", chain: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			scramble := make([]byte, 20)
			sentAfterGreeting := make(chan int, 1)
			go func() {
				// Play an attacker (or a misconfigured proxy) advertising NO TLS in its greeting.
				_ = mysqlwire.WritePacket(server, 0, mysqlwire.ServerGreeting(1, scramble, "8.0-test", false))
				buf := make([]byte, 512)
				n, _ := server.Read(buf) // a correct client writes NOTHING after the greeting
				sentAfterGreeting <- n
				server.Close()
			}()

			// The refusal happens on the greeting, before any TLS config is built, so the chain's contents are
			// never reached.
			_, err := proxyConnect(client, "proxy.example", tc.chain, true, "you@example.com", "sekrit-token", 0)
			client.Close() // unblock the server's Read → EOF (n==0 iff the client sent nothing)

			if err == nil {
				t.Fatal("proxyConnect accepted a plaintext (no-TLS) proxy — the token would cross in the clear")
			}
			if !strings.Contains(err.Error(), "offered none") {
				t.Errorf("expected a downgrade refusal, got: %v", err)
			}
			if n := <-sentAfterGreeting; n != 0 {
				t.Errorf("client sent %d bytes to a no-TLS proxy; the token must never be transmitted", n)
			}
		})
	}
}

// TestProxyConnectAllowsPlaintextOnlyWhenTLSIsNotExpected is the negative control for the test above: a
// genuinely plaintext datasource (wireTLS false) must still work, or the refusal would just be an outage. It
// gets past the greeting and writes a handshake instead of erroring out on it.
func TestProxyConnectAllowsPlaintextOnlyWhenTLSIsNotExpected(t *testing.T) {
	client, server := net.Pipe()
	scramble := make([]byte, 20)
	wroteHandshake := make(chan bool, 1)
	go func() {
		_ = mysqlwire.WritePacket(server, 0, mysqlwire.ServerGreeting(1, scramble, "8.0-test", false))
		// A client that proceeds sends its handshake response here. Reading anything at all is the signal;
		// the exchange is then abandoned, so proxyConnect returns an error either way.
		buf := make([]byte, 512)
		n, _ := server.Read(buf)
		wroteHandshake <- n > 0
		server.Close()
	}()

	_, _ = proxyConnect(client, "proxy.example", "", false, "you@example.com", "sekrit-token", 0)
	client.Close()

	if !<-wroteHandshake {
		t.Error("a plaintext datasource with TLS off must still connect; the refusal must not fire here")
	}
}
