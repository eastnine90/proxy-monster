package pgproxy

import (
	"net"
	"time"
)

const (
	frontendCommandIdleTimeout = 5 * time.Minute
	backendResponseIdleTimeout = 30 * time.Minute
	socketWriteTimeout         = 30 * time.Second
)

// deadlineConn bounds every blocking socket operation after authentication. The read deadline is
// refreshed whenever bytes make progress, so it is an inactivity bound rather than a total query limit.
type deadlineConn struct {
	net.Conn
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func withIODeadlines(conn net.Conn, readTimeout, writeTimeout time.Duration) net.Conn {
	if readTimeout <= 0 && writeTimeout <= 0 {
		return conn
	}
	return &deadlineConn{Conn: conn, readTimeout: readTimeout, writeTimeout: writeTimeout}
}

// switchConn lets a pgproto3 codec retain its buffered reader while the underlying socket changes. During
// frontend startup, strictReads prevents pgproto3's chunk reader from swallowing a pipelined TLS ClientHello;
// during backend startup, it prevents reads beyond ReadyForQuery before dialBackendAuth returns the connection.
type switchConn struct {
	net.Conn
	strictReads bool
}

func (c *switchConn) Read(payload []byte) (int, error) {
	if c.strictReads && len(payload) > 1 {
		payload = payload[:1]
	}
	return c.Conn.Read(payload)
}

func (c *deadlineConn) Read(payload []byte) (int, error) {
	if c.readTimeout > 0 {
		if err := c.SetReadDeadline(time.Now().Add(c.readTimeout)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(payload)
}

func (c *deadlineConn) Write(payload []byte) (int, error) {
	if c.writeTimeout > 0 {
		if err := c.SetWriteDeadline(time.Now().Add(c.writeTimeout)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(payload)
}
