// Package server implements the GoTunnel server (VPS side).
//
// A single TCP listener is shared: connections whose first byte is a
// TLS handshake record are treated as GoTunnel clients (mutual TLS +
// auth + yamux session); all other connections are treated as phone
// proxy connections and forwarded through the active client session.
package server

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"

	"gotunnel/internal/logutil"
	"gotunnel/internal/protocol"
	"gotunnel/internal/proxy"
	"gotunnel/internal/tunnel"
)

// DefaultMaxStreams is the default per-session connection limit.
const DefaultMaxStreams = 256

// Options configures a Server.
type Options struct {
	// ListenAddr is the listen address, e.g. "0.0.0.0:4567".
	ListenAddr string
	// TLSConfig is a mutual-TLS server config (see internal/tlsutil).
	TLSConfig *tls.Config
	// Token, if non-empty, is an additional shared secret the client
	// must present after the TLS handshake.
	Token string
	// MaxStreams limits concurrent proxied connections per session.
	// Zero means DefaultMaxStreams.
	MaxStreams int
	// Logger; nil uses slog.Default().
	Logger *slog.Logger
}

// Server accepts one authorized GoTunnel client session and forwards
// proxy connections through it.
type Server struct {
	opts Options
	log  *slog.Logger

	mu     sync.Mutex
	ln     net.Listener
	sess   *session
	conns  sync.Map // net.Conn -> struct{}, all open connections
	closed atomic.Bool
	warns  *logutil.RateLimiter
}

// session is one connected, authenticated GoTunnel client.
type session struct {
	conn    net.Conn
	yamux   *yamux.Session
	streams atomic.Int32
}

// New creates a Server.
func New(opts Options) *Server {
	if opts.MaxStreams <= 0 {
		opts.MaxStreams = DefaultMaxStreams
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Server{opts: opts, log: log, warns: logutil.New(30 * time.Second)}
}

// Listen binds the listener. Use Addr to discover the bound address.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.opts.ListenAddr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	return nil
}

// Addr returns the bound address, or nil before Listen.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Serve accepts connections until ctx is cancelled or Close is called.
func (s *Server) Serve(ctx context.Context) error {
	s.mu.Lock()
	ln := s.ln
	s.mu.Unlock()
	if ln == nil {
		return errors.New("server: Listen not called")
	}

	// Closing the listener on cancellation unblocks Accept; Close
	// also drops all in-flight connections and the session.
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || s.closed.Load() {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Temporary() {
				continue
			}
			return err
		}
		// Track the connection synchronously before spawning the
		// handler so Close can never miss it.
		s.conns.Store(conn, struct{}{})
		if s.closed.Load() {
			s.conns.Delete(conn)
			_ = conn.Close()
			continue
		}
		go s.handleConn(ctx, conn)
	}
}

// HasSession reports whether an authorized client session is active.
func (s *Server) HasSession() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sess != nil
}

// Close stops the listener, drops the active session, and closes all
// open connections.
func (s *Server) Close() error {
	s.closed.Store(true)
	s.mu.Lock()
	if s.sess != nil {
		_ = s.sess.yamux.Close()
		_ = s.sess.conn.Close()
		s.sess = nil
	}
	ln := s.ln
	s.ln = nil
	s.mu.Unlock()

	s.conns.Range(func(key, _ any) bool {
		if c, ok := key.(net.Conn); ok {
			_ = c.Close()
		}
		s.conns.Delete(key)
		return true
	})

	if ln != nil {
		return ln.Close()
	}
	return nil
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer s.conns.Delete(conn)
	defer conn.Close()

	// Peek one byte to distinguish TLS clients from plain proxy
	// connections sharing the same port.
	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	wrapped := &protocol.BufferedConn{Conn: conn, Reader: br}

	if first[0] == protocol.TLSRecordHandshake {
		s.handleTunnelClient(ctx, wrapped)
		return
	}
	s.handleProxyConn(wrapped)
}

// handleTunnelClient runs mutual TLS + auth, then serves a yamux
// session until it closes or ctx is cancelled.
func (s *Server) handleTunnelClient(ctx context.Context, conn net.Conn) {
	tconn := tls.Server(conn, s.opts.TLSConfig)
	if err := tconn.HandshakeContext(ctx); err != nil {
		s.warns.Record(s.log, "tunnel client TLS handshake failed", "remote", conn.RemoteAddr(), "err", err)
		return
	}
	defer tconn.Close()

	remote := tconn.RemoteAddr().String()

	req, err := protocol.ReadAuth(tconn)
	if err != nil {
		s.warns.Record(s.log, "auth read failed", "remote", remote, "err", err)
		_ = protocol.WriteAuthResult(tconn, false, "malformed auth request")
		return
	}
	if req.Version != protocol.Version {
		_ = protocol.WriteAuthResult(tconn, false, fmt.Sprintf("unsupported protocol version %d", req.Version))
		return
	}
	if s.opts.Token != "" && subtle.ConstantTimeCompare([]byte(req.Token), []byte(s.opts.Token)) != 1 {
		s.warns.Record(s.log, "auth rejected", "remote", remote)
		_ = protocol.WriteAuthResult(tconn, false, "invalid token")
		return
	}
	if err := protocol.WriteAuthResult(tconn, true, ""); err != nil {
		return
	}

	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	ysess, err := yamux.Server(tconn, cfg)
	if err != nil {
		s.warns.Record(s.log, "yamux server failed", "remote", remote, "err", err)
		return
	}

	sess := &session{conn: tconn, yamux: ysess}
	s.setSession(sess)
	s.log.Info("client connected", "remote", remote)
	defer func() {
		s.clearSession(sess)
		_ = ysess.Close()
		s.log.Info("client disconnected", "remote", remote)
	}()

	select {
	case <-ysess.CloseChan():
	case <-ctx.Done():
	}
}

// handleProxyConn forwards one proxy connection (phone) through a new
// yamux stream to the active client.
func (s *Server) handleProxyConn(conn net.Conn) {
	sess := s.currentSession()
	if sess == nil {
		s.serveDirect(conn)
		return
	}

	// Per-session connection limit to avoid resource exhaustion.
	// Reserve a slot atomically before opening the stream.
	if n := sess.streams.Add(1); int(n) > s.opts.MaxStreams {
		sess.streams.Add(-1)
		s.warns.Record(s.log, "proxy connection dropped: per-session stream limit reached",
			"remote", conn.RemoteAddr(), "max", s.opts.MaxStreams)
		return
	}

	stream, err := sess.yamux.Open()
	if err != nil {
		sess.streams.Add(-1)
		s.warns.Record(s.log, "open stream failed", "err", err)
		s.serveDirect(conn)
		return
	}
	defer func() {
		sess.streams.Add(-1)
		_ = stream.Close()
	}()

	defer conn.Close()
	tunnel.Bidirectional(conn, stream)
}

// serveDirect keeps proxy clients working when no GoTunnel client is
// connected. It deliberately does not authenticate phone requests:
// stock Android Wi-Fi proxy settings have no proxy-auth fields.
// WARNING: this makes the server an open HTTP proxy while no client is
// connected. Anyone able to reach the port can use it.
func (s *Server) serveDirect(conn net.Conn) {
	s.warns.Record(s.log, "no client session, proxying directly from server (open proxy)",
		"remote", conn.RemoteAddr())
	proxy.ServeDirect(conn, proxy.Options{
		DialTimeout: 10 * time.Second,
		Logger:      s.log,
		Warns:       s.warns,
	})
}

func (s *Server) setSession(sess *session) {
	s.mu.Lock()
	old := s.sess
	s.sess = sess
	s.mu.Unlock()
	if old != nil {
		// Last connected client wins; clean up the previous session.
		_ = old.yamux.Close()
		_ = old.conn.Close()
	}
}

func (s *Server) clearSession(sess *session) {
	s.mu.Lock()
	if s.sess == sess {
		s.sess = nil
	}
	s.mu.Unlock()
}

func (s *Server) currentSession() *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sess
}
