package tunnel

import (
	"io"
	"net"
	"testing"
	"time"
)

// tcpPair returns two connected TCP conns on localhost.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	res := <-ch
	if res.err != nil {
		t.Fatal(res.err)
	}
	return client, res.c
}

func TestBidirectional(t *testing.T) {
	// a1 <-> a2 and b1 <-> b2; Bidirectional bridges a2 <-> b2.
	a1, a2 := tcpPair(t)
	defer a1.Close()
	b1, b2 := tcpPair(t)
	defer b1.Close()

	done := make(chan struct{})
	go func() {
		Bidirectional(a2, b2)
		close(done)
	}()

	deadline := time.Now().Add(5 * time.Second)
	_ = a1.SetDeadline(deadline)
	_ = b1.SetDeadline(deadline)

	// a1 -> b1
	if _, err := a1.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(b1, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("a1->b1 got %q", buf)
	}

	// b1 -> a1
	if _, err := b1.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(a1, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "world" {
		t.Fatalf("b1->a1 got %q", buf)
	}

	// Closing a1 (write side) propagates half-close; b1 sees EOF.
	_ = a1.(*net.TCPConn).CloseWrite()
	_ = a1.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := b1.Read(buf)
	_ = n
	if err != io.EOF {
		// Half-close propagation must surface EOF on the other side.
		t.Fatalf("expected EOF after half-close, got err=%v", err)
	}

	_ = b1.Close()
	_ = a1.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Bidirectional did not return")
	}
}
