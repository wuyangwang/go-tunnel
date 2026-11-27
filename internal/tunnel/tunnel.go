// Package tunnel implements raw bidirectional TCP forwarding.
package tunnel

import (
	"io"
	"net"
	"sync"
)

// halfCloser is implemented by connections that can close only the
// write side (*net.TCPConn, *tls.Conn, protocol.BufferedConn...).
type halfCloser interface {
	CloseWrite() error
}

// Bidirectional forwards bytes between a and b in both directions until
// both directions finish, propagating half-close, then closes both.
func Bidirectional(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pipe(b, a)
	}()
	go func() {
		defer wg.Done()
		pipe(a, b)
	}()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

// pipe copies src -> dst, then half-closes dst.
func pipe(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	CloseWrite(dst)
}

// CloseWrite half-closes the write side of c. Connections without an
// explicit CloseWrite (e.g. yamux streams, whose Close sends a FIN and
// still allows reads) fall back to Close; closing twice is safe.
func CloseWrite(c net.Conn) {
	if cw, ok := c.(halfCloser); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
