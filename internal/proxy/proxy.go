// Package proxy implements a minimal HTTP proxy (absolute-form requests
// and CONNECT). It is used as a fail-open fallback by the server when no
// authorized GoTunnel client is connected, and by the client when the
// local Charles proxy is unavailable.
package proxy

import (
	"bufio"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	"gotunnel/internal/logutil"
	"gotunnel/internal/protocol"
	"gotunnel/internal/tunnel"
)

// Options configures ServeDirect.
type Options struct {
	DialTimeout time.Duration
	// Authorize checks the parsed proxy request headers. If nil, all
	// requests are allowed (only safe when access is otherwise gated).
	Authorize func(headers map[string]string) bool
	Logger    *slog.Logger
	Warns     *logutil.RateLimiter
}

// ServeDirect reads one proxy request from conn, dials the requested
// target, and relays bytes. It consumes the request headers itself so
// the caller must not have read past them.
func ServeDirect(conn net.Conn, opts Options) {
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 5 * time.Second
	}

	_ = conn.SetReadDeadline(time.Now().Add(opts.DialTimeout))
	br := bufio.NewReader(conn)
	line, err := br.ReadSlice('\n')
	if err != nil {
		return
	}
	fields := strings.Fields(string(line))
	if len(fields) < 2 {
		return
	}

	headers := make(map[string]string)
	var headerLines []string
	for {
		h, err := br.ReadSlice('\n')
		if err != nil {
			return
		}
		if isBlankLine(h) {
			break
		}
		headerLines = append(headerLines, string(h))
		k, v, ok := strings.Cut(string(h), ":")
		if ok {
			headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	_ = conn.SetReadDeadline(time.Time{})

	if opts.Authorize != nil && !opts.Authorize(headers) {
		_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\n"+
			"Proxy-Authenticate: Basic realm=\"gotunnel\"\r\nContent-Length: 0\r\n\r\n")
		return
	}

	wrapped := &protocol.BufferedConn{Conn: conn, Reader: br}
	method, target := fields[0], fields[1]
	isConnect := strings.EqualFold(method, "CONNECT")

	var addr string
	if isConnect {
		addr = target
	} else if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		u, err := url.Parse(target)
		if err != nil || u.Host == "" {
			return
		}
		addr = u.Host
		if u.Port() == "" {
			port := "80"
			if u.Scheme == "https" {
				port = "443"
			}
			addr = net.JoinHostPort(u.Hostname(), port)
		}
	} else {
		return
	}

	remote, err := net.DialTimeout("tcp", addr, opts.DialTimeout)
	if err != nil {
		if opts.Warns != nil && opts.Logger != nil {
			opts.Warns.Record(opts.Logger, "direct proxy dial failed", "target", addr, "err", err)
		}
		_, _ = io.WriteString(wrapped, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer remote.Close()

	if isConnect {
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
	} else {
		version := "HTTP/1.1"
		if len(fields) >= 3 {
			version = fields[2]
		}
		u, _ := url.Parse(target)
		var request strings.Builder
		request.WriteString(method + " " + u.RequestURI() + " " + version + "\r\n")
		for _, h := range headerLines {
			request.WriteString(h)
		}
		request.WriteString("\r\n")
		if _, err := io.WriteString(remote, request.String()); err != nil {
			return
		}
	}
	tunnel.Bidirectional(wrapped, remote)
}

func isBlankLine(b []byte) bool {
	return (len(b) == 2 && b[0] == '\r' && b[1] == '\n') || (len(b) == 1 && b[0] == '\n')
}

// AuthorizeBasicToken returns an Authorize func accepting Basic proxy
// credentials whose password equals token. When token is empty it
// returns nil (no auth enforced).
func AuthorizeBasicToken(token string) func(map[string]string) bool {
	if token == "" {
		return nil
	}
	return func(headers map[string]string) bool {
		value, ok := headers["proxy-authorization"]
		if !ok || !strings.HasPrefix(strings.ToLower(value), "basic ") {
			return false
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[6:]))
		if err != nil {
			return false
		}
		_, password, ok := strings.Cut(string(decoded), ":")
		return ok && subtle.ConstantTimeCompare([]byte(password), []byte(token)) == 1
	}
}
