// Package client implements the GoTunnel client (PC side).
//
// The client dials out to the VPS (it never listens on any port, so
// the local Charles proxy is not exposed publicly), establishes mutual
// TLS + auth, then a yamux session, and for every accepted stream
// connects to the local proxy (Charles) and forwards bidirectionally.
// On disconnection it reconnects with backoff; requests in flight
// during a disconnect are not preserved.
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"gotunnel/internal/protocol"
	"gotunnel/internal/tunnel"
)

// Options configures the client.
type Options struct {
	// ServerAddr is the VPS address, e.g. "1.2.3.4:4567".
	ServerAddr string
	// LocalAddr is the local proxy to forward to, e.g. "127.0.0.1:8890".
	LocalAddr string
	// TLSConfig is a mutual-TLS client config (see internal/tlsutil).
	TLSConfig *tls.Config
	// Token, if set, must match the server's token.
	Token string
	// ReconnectDelay between reconnect attempts. Default 1s.
	ReconnectDelay time.Duration
	// DialTimeout for dialing server and local proxy. Default 5s.
	DialTimeout time.Duration
	// Logger; nil uses slog.Default().
	Logger *slog.Logger
}

// Run connects and reconnects until ctx is cancelled.
func Run(ctx context.Context, opts Options) error {
	if opts.ReconnectDelay <= 0 {
		opts.ReconnectDelay = time.Second
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 5 * time.Second
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	failures := &failureLogger{interval: 30 * time.Second}

	for {
		err := runOnce(ctx, opts, log, failures)
		if ctx.Err() != nil {
			return nil
		}
		var authErr *AuthError
		if errors.As(err, &authErr) {
			// Retrying with the same credentials would always fail.
			return err
		}
		if err != nil {
			log.Warn("connection lost, reconnecting", "err", err, "delay", opts.ReconnectDelay)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(opts.ReconnectDelay):
		}
	}
}

// runOnce establishes one TLS + yamux session and serves streams
// until the session dies or ctx is cancelled.
func runOnce(ctx context.Context, opts Options, log *slog.Logger, failures *failureLogger) error {
	dialer := net.Dialer{Timeout: opts.DialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", opts.ServerAddr)
	if err != nil {
		return err
	}

	tconn := tls.Client(raw, opts.TLSConfig)
	if err := tconn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return err
	}
	if err := tconn.SetDeadline(time.Now().Add(opts.DialTimeout)); err != nil {
		tconn.Close()
		return err
	}

	if err := protocol.WriteAuth(tconn, protocol.AuthRequest{Version: protocol.Version, Token: opts.Token}); err != nil {
		tconn.Close()
		return err
	}
	ok, msg, err := protocol.ReadAuthResult(tconn)
	if err != nil {
		tconn.Close()
		return err
	}
	if !ok {
		tconn.Close()
		return &AuthError{Message: msg}
	}
	if err := tconn.SetDeadline(time.Time{}); err != nil { // clear deadline
		tconn.Close()
		return err
	}

	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	sess, err := yamux.Client(tconn, cfg)
	if err != nil {
		tconn.Close()
		return err
	}
	defer sess.Close()

	log.Info("connected to server", "server", opts.ServerAddr, "local", opts.LocalAddr)

	// Cancelled context tears down the session.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = sess.Close()
		case <-done:
		}
	}()

	for {
		stream, err := sess.Accept()
		if err != nil {
			return err
		}
		go serveStream(stream, opts, log, failures)
	}
}

// serveStream connects to the local proxy and pipes the stream.
func serveStream(stream net.Conn, opts Options, log *slog.Logger, failures *failureLogger) {
	defer stream.Close()
	local, err := net.DialTimeout("tcp", opts.LocalAddr, opts.DialTimeout)
	if err != nil {
		failures.record(log, opts.LocalAddr, err)
		return
	}
	failures.recovered(log, opts.LocalAddr)
	defer local.Close()
	tunnel.Bidirectional(stream, local)
}

// failureLogger rate-limits repeated local-proxy dial errors so a phone
// retrying rapidly cannot flood the log. First failure logs immediately;
// further ones are counted and summarized at most once per interval.
type failureLogger struct {
	mu       sync.Mutex
	last     time.Time
	pending  int
	interval time.Duration
}

func (f *failureLogger) record(log *slog.Logger, local string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending++
	now := time.Now()
	if !f.last.IsZero() && now.Sub(f.last) < f.interval {
		return
	}
	suppressed := f.pending - 1
	f.pending = 0
	f.last = now
	if suppressed > 0 {
		log.Warn("local proxy dial failed", "local", local, "err", err, "suppressed", suppressed)
		return
	}
	log.Warn("local proxy dial failed", "local", local, "err", err)
}

func (f *failureLogger) recovered(log *slog.Logger, local string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pending == 0 {
		return
	}
	f.pending = 0
	f.last = time.Time{}
	log.Info("local proxy available again", "local", local)
}

// AuthError is returned when the server rejects authentication.
type AuthError struct{ Message string }

func (e *AuthError) Error() string { return "authentication rejected: " + e.Message }
