// Package protocol defines the wire protocol shared by GoTunnel server and
// client: version constants, protocol detection, and the authentication
// handshake performed inside the TLS connection before yamux starts.
package protocol

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

const (
	// Version is the protocol version sent in the auth handshake.
	Version = 1

	// DefaultServerPort is the default listen port of gotunnel-server.
	DefaultServerPort = 4567

	// DefaultClientPort is the default local forward target port
	// (the PC's Charles proxy).
	DefaultClientPort = 8890

	// TLSRecordHandshake is the first byte of a TLS handshake record.
	// GoTunnel clients always speak TLS; plain HTTP proxy clients never
	// start with this byte, which lets the server share one port.
	TLSRecordHandshake = 0x16

	// authPrefix identifies an auth request line.
	authPrefix = "GOTUNNEL"

	// maxAuthLine bounds the auth line length to avoid memory abuse.
	maxAuthLine = 4096
)

// AuthRequest is sent by the client right after the TLS handshake,
// before the yamux session starts.
type AuthRequest struct {
	Version int
	Token   string
}

// WriteAuth sends an auth request as a single line:
// "GOTUNNEL/<version>[ <token>]\n".
func WriteAuth(w io.Writer, req AuthRequest) error {
	if strings.ContainsAny(req.Token, " \t\r\n") {
		return errors.New("protocol: token must not contain whitespace")
	}
	line := fmt.Sprintf("%s/%d", authPrefix, req.Version)
	if req.Token != "" {
		line += " " + req.Token
	}
	_, err := io.WriteString(w, line+"\n")
	return err
}

// ReadAuth reads a single auth line. It reads one byte at a time so it
// never consumes bytes belonging to the yamux session that follows.
func ReadAuth(r io.Reader) (AuthRequest, error) {
	line, err := readLine(r)
	if err != nil {
		return AuthRequest{}, err
	}
	var req AuthRequest
	fields := strings.SplitN(line, " ", 2)
	head := fields[0]
	if len(fields) == 2 {
		req.Token = fields[1]
	}
	prefix, version, ok := strings.Cut(head, "/")
	if !ok || prefix != authPrefix {
		return AuthRequest{}, fmt.Errorf("protocol: malformed auth request %q", line)
	}
	if _, err := fmt.Sscanf(version, "%d", &req.Version); err != nil {
		return AuthRequest{}, fmt.Errorf("protocol: malformed version in %q", line)
	}
	return req, nil
}

// WriteAuthResult sends "OK\n" or "ERR <message>\n".
func WriteAuthResult(w io.Writer, ok bool, message string) error {
	if ok {
		_, err := io.WriteString(w, "OK\n")
		return err
	}
	message = sanitize(message)
	if message == "" {
		message = "authentication failed"
	}
	_, err := io.WriteString(w, "ERR "+message+"\n")
	return err
}

// ReadAuthResult reads the server's response to the auth request.
func ReadAuthResult(r io.Reader) (ok bool, message string, err error) {
	line, err := readLine(r)
	if err != nil {
		return false, "", err
	}
	if line == "OK" {
		return true, "", nil
	}
	if msg, found := strings.CutPrefix(line, "ERR "); found {
		return false, msg, nil
	}
	if line == "ERR" {
		return false, "", nil
	}
	return false, "", fmt.Errorf("protocol: malformed auth result %q", line)
}

// readLine reads until '\n', one byte at a time, to avoid reading past
// the end of the line into a following protocol (e.g. yamux).
func readLine(r io.Reader) (string, error) {
	var sb strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n == 1 {
			c := buf[0]
			if c == '\n' {
				break
			}
			if c != '\r' {
				sb.WriteByte(c)
			}
			if sb.Len() > maxAuthLine {
				return "", errors.New("protocol: line too long")
			}
		}
		if err != nil {
			if err == io.EOF && sb.Len() > 0 {
				break
			}
			return "", err
		}
	}
	return sb.String(), nil
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(s)
}

// BufferedConn replays bytes already buffered in a bufio.Reader before
// reading from the underlying connection. It is used for protocol
// sniffing and for forwarding after peeking.
type BufferedConn struct {
	net.Conn
	Reader *bufio.Reader
}

// Read reads from the buffered reader first.
func (c *BufferedConn) Read(p []byte) (int, error) { return c.Reader.Read(p) }

// CloseWrite half-closes the underlying connection if it supports it.
func (c *BufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
