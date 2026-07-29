package daemon

import (
	"crypto/rand"
	"io"
	"net"
	"time"

	"github.com/ridi-oss/proxy-monster/mysqlwire"
)

// brokerMySQL plays MySQL server to the local client, dials the datasource's proxy (bounded by dialTimeout),
// authenticates there with the token as the cleartext password, then pipes the command phase raw. When
// certChainPEM is set the upstream TLS verifies against it as the root pool, with the advertised host checked
// against it; otherwise it falls back to the system trust store. When wireTLS says this proxy serves TLS, a
// greeting offering none is refused rather than sent the token in plaintext.
func brokerMySQL(local net.Conn, proxyAddr, certChainPEM string, wireTLS bool, principal, token string) error {
	scramble := make([]byte, 20)
	if _, err := rand.Read(scramble); err != nil {
		return err
	}
	clientCaps, err := localServerGreet(local, scramble)
	if err != nil {
		return err
	}
	proxy, err := net.DialTimeout("tcp", proxyAddr, dialTimeout)
	if err != nil {
		_ = mysqlwire.WritePacket(local, 2, mysqlwire.ErrPacket(1045, "proxy-monster: cannot reach proxy"))
		return err
	}
	defer proxy.Close()

	// Bound the HANDSHAKE, not just the dial. DialTimeout only covers refusal: a proxy that accepts and then
	// goes silent (black-holed load balancer, stalled TLS peer) would otherwise park this goroutine and its two
	// sockets forever, and neither a logout nor a revocation can end it — closing the local side does not
	// unblock a read on the upstream one. Cleared before the relay, which is long-lived by design.
	if err := proxy.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return err
	}
	up, err := proxyConnect(proxy, hostOf(proxyAddr), certChainPEM, wireTLS, principal, token, clientCaps)
	if err != nil {
		_ = mysqlwire.WritePacket(local, 2, mysqlwire.ErrPacket(1045, "proxy-monster: "+err.Error()))
		return err
	}
	// The relay has no time bound — a session may idle legitimately — so drop the handshake deadline.
	if err := proxy.SetDeadline(time.Time{}); err != nil {
		return err
	}
	if err := mysqlwire.WritePacket(local, 2, mysqlwire.OKPacket()); err != nil {
		return err
	}
	pipe(up, local)
	return nil
}

// pipe copies bytes both directions until either side closes.
func pipe(up io.ReadWriter, local net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, local); done <- struct{}{} }()
	go func() { _, _ = io.Copy(local, up); done <- struct{}{} }()
	<-done
}

// hostOf returns the host part of a host:port (the TLS server name), or the input unchanged if it has no port.
func hostOf(hostPort string) string {
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		return h
	}
	return hostPort
}
