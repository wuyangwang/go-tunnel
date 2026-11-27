// Package client implements the GoTunnel client (PC side).
//
// The client dials out to the VPS (it never listens on any port), sets up
// mutual TLS + auth, then a yamux session. For each stream it prefers the
// local Charles proxy (127.0.0.1:8890) so traffic can be captured. If the
// local proxy cannot be reached, it falls back to acting as a minimal
// HTTP proxy itself and dials the requested target directly, so the
// phone keeps working even when Charles is not running (that traffic is
// not captured and egresses from the PC).
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/hashicorp/yamux"

	"gotunnel/internal/logutil"
	"gotunnel/internal/protocol"
	"gotunnel/internal/proxy"
	"gotunnel/internal/tunnel"
)

const dialFailedMsg = "local proxy dial failed"

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
	// DialTimeout for dialing server, local proxy and direct targets. Default 5s.
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
	warns := logutil.New(30 * time.Second)

	for {
		err := runOnce(ctx, opts, log, warns)
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

// runOnce establishes one TLS + yamux session and serves streams until
// the session dies or ctx is cancelled.
func runOnce(ctx context.Context, opts Options, log *slog.Logger, warns *logutil.RateLimiter) error {
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
		go serveStream(stream, opts, log, warns)
	}
}

// serveStream prefers the local proxy and falls back to direct proxying.
func serveStream(stream net.Conn, opts Options, log *slog.Logger, warns *logutil.RateLimiter) {
	defer stream.Close()
	local, err := net.DialTimeout("tcp", opts.LocalAddr, opts.DialTimeout)
	if err == nil {
		if warns.Reset(dialFailedMsg) {
			log.Info("local proxy available again", "local", opts.LocalAddr)
		}
		defer local.Close()
		tunnel.Bidirectional(stream, local)
		return
	}
	warns.Record(log, dialFailedMsg, "local", opts.LocalAddr, "err", err)
	proxy.ServeDirect(stream, proxy.Options{
		DialTimeout: opts.DialTimeout,
		Logger:      log,
		Warns:       warns,
	})
}

// AuthError is returned when the server rejects authentication.
type AuthError struct{ Message string }

func (e *AuthError) Error() string { return "authentication rejected: " + e.Message }
