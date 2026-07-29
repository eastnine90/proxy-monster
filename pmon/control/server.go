package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/state"
)

// Backend is what the daemon implements for the control API to drive. It exists so the socket server holds no
// daemon state of its own and the daemon holds no HTTP concerns.
type Backend interface {
	// Status is the daemon's current observable state.
	Status() Status
	// Login runs a device-auth flow, reporting each step through onEvent. It returns when the flow finishes.
	Login(ctx context.Context, req LoginRequest, onEvent func(LoginEvent)) error
	// Logout clears credentials and closes brokers, leaving the daemon idle.
	Logout() error
	// Reload forces an immediate rediscovery.
	Reload()
	// Subscribe opens a state-change stream; the returned cancel must be called when the stream ends.
	Subscribe() (<-chan Event, func())
	// Shutdown asks the daemon to exit gracefully.
	Shutdown()
}

// Server serves the control API on the daemon's unix socket.
type Server struct {
	backend Backend
	ln      net.Listener
	srv     *http.Server
}

// Listen binds the control socket, recovering from a stale one left by a killed daemon.
//
// A crashed daemon leaves the socket file behind, so bind fails with EADDRINUSE. The disambiguation is the
// pid lock, not a connect probe: this is called by a daemon that has ALREADY taken the lock, so any socket
// file present now is necessarily stale and safe to unlink.
func Listen(backend Backend) (*Server, error) {
	if _, err := state.EnsureDir(); err != nil {
		return nil, err
	}
	sock, err := state.SocketPath()
	if err != nil {
		return nil, err
	}
	if err := os.Remove(sock); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("could not clear the stale control socket %s: %w", sock, err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", sock, err)
	}
	// Belt to the directory's 0700: even if the directory mode were loosened, the socket itself stays
	// owner-only. Together with the directory, this IS the control API's authentication.
	if err := os.Chmod(sock, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("chmod %s: %w", sock, err)
	}

	s := &Server{backend: backend, ln: ln}
	mux := http.NewServeMux()
	mux.HandleFunc(PathStatus, s.handleStatus)
	mux.HandleFunc(PathLogin, s.handleLogin)
	mux.HandleFunc(PathLogout, s.handleLogout)
	mux.HandleFunc(PathReload, s.handleReload)
	mux.HandleFunc(PathShutdown, s.handleShutdown)
	mux.HandleFunc(PathEvents, s.handleEvents)
	s.srv = &http.Server{Handler: mux}
	return s, nil
}

// Serve runs the control API until ctx ends, then closes the socket.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		// Close rather than Shutdown: /login and /events are long-lived streams whose handlers exit on their
		// own ctx, and a graceful Shutdown would block on them.
		s.srv.Close()
	}()
	err := s.srv.Serve(s.ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close stops serving and removes the socket file.
func (s *Server) Close() {
	s.srv.Close()
	if sock, err := state.SocketPath(); err == nil {
		os.Remove(sock)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, ErrorResponse{Error: err.Error()})
}

// requireMethod rejects a mismatched method, so a GET can't trigger a login.
func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("%s requires %s", r.URL.Path, method))
		return false
	}
	return true
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, s.backend.Status())
}

// handleLogin streams the flow's steps as newline-delimited JSON, so the peer shows the verification prompt
// the moment it exists rather than after the whole flow completes.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req LoginRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req) // an empty body is valid: reuse the saved control plane
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	var mu sync.Mutex
	emit := func(ev LoginEvent) {
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(ev)
		if flusher != nil {
			flusher.Flush()
		}
	}
	if err := s.backend.Login(r.Context(), req, emit); err != nil {
		emit(LoginEvent{Kind: "error", Error: err.Error()})
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if err := s.backend.Logout(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, s.backend.Status())
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	s.backend.Reload()
	writeJSON(w, http.StatusOK, s.backend.Status())
}

func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopping"})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	s.backend.Shutdown()
}

// eventKeepalive bounds how long /events can sit silent, so a peer notices a dead socket promptly.
const eventKeepalive = 30 * time.Second

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	events, cancel := s.backend.Subscribe()
	defer cancel()

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)

	// Send the current state immediately, so a peer renders correctly without a separate /status call.
	current := s.backend.Status()
	if err := enc.Encode(Event{Kind: "status", Status: &current}); err != nil {
		return
	}
	if flusher != nil {
		flusher.Flush()
	}

	t := time.NewTicker(eventKeepalive)
	defer t.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			if err := enc.Encode(ev); err != nil {
				return
			}
		case <-t.C:
			// A bare newline: harmless to the peer's line decoder, and it surfaces a broken pipe.
			if _, err := w.Write([]byte("\n")); err != nil {
				return
			}
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}
