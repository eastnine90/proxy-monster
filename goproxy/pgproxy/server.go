// Package pgproxy is the blocking PostgreSQL wire broker for the simple and extended query protocols.
// It owns only wire I/O and mechanically applies engine verdicts; authorization remains exclusively in
// engine.QueryEngine. COPY is deferred to a later phase.
package pgproxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const (
	maxConcurrentConnections = 256
	maxBackendGeneration     = uint64(1<<63 - 1)
)

var backendGeneration atomic.Uint64

// Server is a blocking goroutine-per-connection PostgreSQL wire broker.
type Server struct {
	port        int
	backend     spi.BackendTarget
	client      spi.EnforcementClient
	db          engine.Db
	tlsProvider func() (*tls.Config, error)

	mu        sync.Mutex
	ln        net.Listener
	connSlots chan struct{}
}

// New constructs a PostgreSQL wire broker for one backend datasource.
func New(port int, backend spi.BackendTarget, client spi.EnforcementClient, dbImpl engine.Db, tlsProvider func() (*tls.Config, error)) *Server {
	return &Server{
		port:        port,
		backend:     backend,
		client:      client,
		db:          dbImpl,
		tlsProvider: tlsProvider,
		connSlots:   make(chan struct{}, maxConcurrentConnections),
	}
}

// Listen binds the configured TCP port. Port zero requests an ephemeral port for tests.
func (s *Server) Listen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		return errors.New("pgproxy: already listening")
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return err
	}
	s.ln = ln
	return nil
}

// Serve accepts client connections and handles each on its own goroutine. The bounded slot pool prevents
// unauthenticated sockets from creating an unbounded goroutine population.
func (s *Server) Serve() error {
	s.mu.Lock()
	ln := s.ln
	s.mu.Unlock()
	if ln == nil {
		return errors.New("pgproxy: Listen must be called before Serve")
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if !s.acquireConnection() {
			_ = conn.Close()
			continue
		}
		go func() {
			defer s.releaseConnection()
			defer func() {
				if recovered := recover(); recovered != nil {
					_ = conn.Close()
					slog.Error(
						"postgres connection handler panicked",
						"client", conn.RemoteAddr().String(),
						"panic", recovered,
						"stack", string(debug.Stack()),
					)
				}
			}()
			s.handleConn(conn)
		}()
	}
}

func (s *Server) acquireConnection() bool {
	select {
	case s.connSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) releaseConnection() { <-s.connSlots }

// Start binds the configured port and blocks in the accept loop.
func (s *Server) Start() error {
	if err := s.Listen(); err != nil {
		return err
	}
	return s.Serve()
}

// Shutdown closes the listener. An accept loop blocked in Serve returns nil.
func (s *Server) Shutdown() {
	s.mu.Lock()
	ln := s.ln
	s.ln = nil
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
}

// Addr returns the bound listener address, or nil before Listen.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}
