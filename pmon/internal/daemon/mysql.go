package daemon

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

// pmon-specific MySQL handshake flows. The daemon's local broker acts as a MySQL *server* to the
// local client (greeting → accept any auth → OK) and as a MySQL *client* to the proxy (handshake →
// auth-switch → send the token as the cleartext password). After both handshakes the command phase
// is piped raw. The low-level framing/message primitives live in the shared mysqlwire package.

// serverVersion is what pmon's local broker reports to the client in its greeting.
const serverVersion = "8.0.40-proxy-monster-pm"

// localServerGreet plays the MySQL server to the local client up to (not including) the auth
// result: greeting, then read its handshake response (auth ignored — the trust boundary is the
// upstream token). The caller sends OK only after the upstream proxy handshake succeeds, so a bad
// token surfaces as an auth error to the local client rather than a late failure.
func localServerGreet(c io.ReadWriter, scramble []byte) (clientCaps uint32, err error) {
	// false: this greeting must not advertise CapConnectWithDB — the handshake response below is read
	// only for its capability flags (clientCaps), never for a handshake-supplied database, so a client
	// connecting with one here would have it silently dropped rather than relayed upstream.
	if err = mysqlwire.WritePacket(c, 0, mysqlwire.ServerGreeting(1, scramble, serverVersion, false)); err != nil {
		return
	}
	_, resp, err := mysqlwire.ReadPacket(c) // handshake response (seq 1)
	if err != nil {
		return
	}
	if len(resp) >= 4 {
		clientCaps = binary.LittleEndian.Uint32(resp[:4])
	}
	return
}

// proxyConnect authenticates to the proxy as [principal], answering its clear-password auth-switch with
// [token]. If the proxy offers CLIENT_SSL it upgrades to TLS *before* sending the handshake (so the token
// never crosses in the clear). When [certChainPEM] is set — the chain the control plane advertised for this
// datasource — TLS verifies against it as the root pool with [serverName] checked; when empty, TLS (if
// offered) verifies against the system trust store.
//
// [wireTLS] is what makes the plaintext refusal safe, and it is deliberately NOT inferred from
// [certChainPEM]: the control plane reports the TLS requirement separately, because a proxy can serve TLS
// while publishing no chain (a publicly-trusted cert, PM_TLS_NO_ADVERTISE) and a transient cert read
// publishes none either. Gating on the chain instead would mean an on-path attacker who answers with a
// no-TLS greeting is indistinguishable from a datasource that never had TLS, and the token would go out in
// the clear.
//
// Returns the connection to pipe the command phase over — the TLS conn when upgraded, else [raw] — or an
// error (with the proxy's message) if auth fails.
func proxyConnect(raw net.Conn, serverName, certChainPEM string, wireTLS bool, principal, token string, clientCaps uint32) (io.ReadWriter, error) {
	gSeq, greeting, err := mysqlwire.ReadPacket(raw) // greeting (seq 0)
	if err != nil {
		return nil, err
	}
	caps := uint32(mysqlwire.CapProtocol41 | mysqlwire.CapSecureConn | mysqlwire.CapPluginAuth | mysqlwire.CapTransactions)
	// Mirror the client's DEPRECATE_EOF so the proxy's result-set framing matches what we pipe back.
	if clientCaps&mysqlwire.CapDeprecateEOF != 0 {
		caps |= mysqlwire.CapDeprecateEOF
	}

	offersSSL := mysqlwire.GreetingOffersSSL(greeting)
	// A datasource the control plane says serves TLS must not be downgraded to plaintext: something offering
	// none is either misconfigured or not the proxy we meant to reach.
	if wireTLS && !offersSSL {
		return nil, fmt.Errorf("the control plane says this datasource's proxy serves TLS but the greeting offered none — refusing to send the token in plaintext")
	}

	var conn io.ReadWriter = raw
	respSeq := gSeq + 1 // handshake response is seq 1 in the plaintext flow
	if offersSSL {
		caps |= mysqlwire.CapSSL
		// SSLRequest (seq 1) → TLS handshake → real handshake (seq 2) over the encrypted conn.
		if err := mysqlwire.WritePacket(raw, gSeq+1, mysqlwire.SSLRequest(caps)); err != nil {
			return nil, err
		}
		tlsCfg, cfgErr := upstreamTLSConfig(serverName, certChainPEM)
		if cfgErr != nil {
			return nil, cfgErr
		}
		tlsConn := tls.Client(raw, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			return nil, fmt.Errorf("TLS handshake with proxy failed: %w", err)
		}
		conn = tlsConn
		respSeq = gSeq + 2
	}

	if err := mysqlwire.WritePacket(conn, respSeq, mysqlwire.ClientHandshakeResponse(caps, principal, []byte{})); err != nil {
		return nil, err
	}
	sSeq, sw, err := mysqlwire.ReadPacket(conn) // expect AuthSwitchRequest (0xfe)
	if err != nil {
		return nil, err
	}
	if len(sw) > 0 && sw[0] == 0xff {
		return nil, fmt.Errorf("%s", mysqlwire.ErrString(sw))
	}
	if len(sw) == 0 || sw[0] != 0xfe {
		return nil, fmt.Errorf("unexpected auth handshake from proxy")
	}
	if err := mysqlwire.WritePacket(conn, sSeq+1, []byte(token)); err != nil { // clear-password = token
		return nil, err
	}
	_, res, err := mysqlwire.ReadPacket(conn) // OK or ERR
	if err != nil {
		return nil, err
	}
	if len(res) > 0 && res[0] == 0xff {
		return nil, fmt.Errorf("%s", mysqlwire.ErrString(res))
	}
	if len(res) > 0 && res[0] == 0x00 {
		return conn, nil
	}
	return nil, fmt.Errorf("unexpected auth result from proxy")
}

// upstreamTLSConfig returns the client TLS config for the upstream proxy hop. The control plane advertises
// the certificate CHAIN to trust for this datasource, so verification is ORDINARY TLS: that chain is the
// root pool, and serverName is checked against it. A self-signed wire cert works because it is its own
// anchor — nothing has to enter the system trust store, and no custom verifier is involved.
//
// This replaced a leaf-fingerprint pin, which had to set InsecureSkipVerify to work and so turned OFF the
// hostname check — a stolen leaf replayed on a different host satisfied it. Chain verification gains that
// hostname binding and is the same verification every other TLS client performs; the tradeoff is that
// identity widens from one exact leaf to any valid certificate for this name under the advertised anchors.
// For a self-signed leaf those are the same thing.
//
// An empty chain falls back to system trust, for a proxy fronted by a publicly-trusted cert. That fallback is
// NOT what decides whether TLS is required — see proxyConnect's wireTLS.
//
// Every certificate in the PEM becomes a trust anchor, INCLUDING the leaf (Go trusts a certificate found
// directly in the roots pool). So a contaminated bundle widens trust rather than failing closed, which is why
// the control plane inspects the chain at registration and warns about anything it cannot verify a path
// through.
func upstreamTLSConfig(serverName, certChainPEM string) (*tls.Config, error) {
	if certChainPEM == "" {
		return &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}, nil
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(certChainPEM)) {
		return nil, fmt.Errorf("the advertised wire cert chain for this datasource contains no usable certificate")
	}
	return &tls.Config{ServerName: serverName, RootCAs: roots, MinVersion: tls.VersionTLS12}, nil
}
