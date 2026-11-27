package server_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"gotunnel/internal/client"
	"gotunnel/internal/server"
	"gotunnel/internal/tlsutil"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// startEcho starts a trivial local "Charles": echoes everything back.
func startEcho(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln
}

func TestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	if err := tlsutil.Generate(dir, nil); err != nil {
		t.Fatal(err)
	}
	sTLS, err := tlsutil.LoadServerConfig(dir+"/server.pem", dir+"/server-key.pem", dir+"/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	cTLS, err := tlsutil.LoadClientConfig(dir+"/client.pem", dir+"/client-key.pem", dir+"/ca.pem", "")
	if err != nil {
		t.Fatal(err)
	}

	echo := startEcho(t)
	defer echo.Close()

	srv := server.New(server.Options{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  sTLS,
		Logger:     discardLogger(),
	})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	clientDone := make(chan error, 1)
	go func() {
		clientDone <- client.Run(ctx, client.Options{
			ServerAddr: srv.Addr().String(),
			LocalAddr:  echo.Addr().String(),
			TLSConfig:  cTLS,
			Logger:     discardLogger(),
		})
	}()

	serverAddr := srv.Addr().String()

	// Wait until the client session is up and forwarding works.
	payload := []byte("GET http://example.com/ HTTP/1.1\r\n\r\n")
	var lastErr error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if err := roundTrip(serverAddr, payload); err == nil {
			lastErr = nil
			break
		} else {
			lastErr = err
			time.Sleep(20 * time.Millisecond)
		}
	}
	if lastErr != nil {
		t.Fatalf("round trip never succeeded: %v", lastErr)
	}

	// Multiple concurrent requests through the same tunnel.
	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			data := []byte(fmt.Sprintf("stream-%d-payload", i))
			if err := roundTrip(serverAddr, data); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent round trip failed: %v", err)
	}

	// HTTP CONNECT-style passthrough is raw TCP; verify byte passthrough.
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(req))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(req) {
		t.Fatalf("CONNECT passthrough mismatch: %q", got)
	}
}

func roundTrip(serverAddr string, payload []byte) error {
	conn, err := net.DialTimeout("tcp", serverAddr, time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if string(got) != string(payload) {
		return fmt.Errorf("got %q want %q", got, payload)
	}
	return nil
}

func TestMaxStreamsPerSession(t *testing.T) {
	dir := t.TempDir()
	if err := tlsutil.Generate(dir, nil); err != nil {
		t.Fatal(err)
	}
	sTLS, err := tlsutil.LoadServerConfig(dir+"/server.pem", dir+"/server-key.pem", dir+"/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	cTLS, err := tlsutil.LoadClientConfig(dir+"/client.pem", dir+"/client-key.pem", dir+"/ca.pem", "")
	if err != nil {
		t.Fatal(err)
	}

	echo := startEcho(t)
	defer echo.Close()

	srv := server.New(server.Options{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  sTLS,
		MaxStreams: 1,
		Logger:     discardLogger(),
	})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	serverAddr := srv.Addr().String()
	clientDone := make(chan error, 1)
	go func() {
		clientDone <- client.Run(ctx, client.Options{
			ServerAddr: serverAddr,
			LocalAddr:  echo.Addr().String(),
			TLSConfig:  cTLS,
			Logger:     discardLogger(),
		})
	}()

	// Wait for session + streaming to work.
	for deadline := time.Now().Add(5 * time.Second); ; {
		if err := roundTrip(serverAddr, []byte("warmup")); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("session never ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// phone1 holds its connection (and its stream) open.
	phone1, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer phone1.Close()
	_ = phone1.SetDeadline(time.Now().Add(5 * time.Second))
	p1 := []byte("one")
	if _, err := phone1.Write(p1); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(p1))
	if _, err := io.ReadFull(phone1, got); err != nil {
		t.Fatal(err)
	}

	// With the single stream slot taken, a second proxy connection is dropped.
	phone2, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer phone2.Close()
	_ = phone2.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := phone2.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if n, err := phone2.Read(buf); n != 0 || err == nil {
		t.Fatalf("expected dropped connection, got n=%d err=%v", n, err)
	}
}

func TestProxyDroppedWithoutClientSession(t *testing.T) {
	dir := t.TempDir()
	if err := tlsutil.Generate(dir, nil); err != nil {
		t.Fatal(err)
	}
	sTLS, err := tlsutil.LoadServerConfig(dir+"/server.pem", dir+"/server-key.pem", dir+"/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(server.Options{ListenAddr: "127.0.0.1:0", TLSConfig: sTLS, Logger: discardLogger()})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	// No client session: server must close the connection.
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected connection to be closed when no client session")
	}
}

func TestTokenRequired(t *testing.T) {
	dir := t.TempDir()
	if err := tlsutil.Generate(dir, nil); err != nil {
		t.Fatal(err)
	}
	sTLS, err := tlsutil.LoadServerConfig(dir+"/server.pem", dir+"/server-key.pem", dir+"/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	cTLS, err := tlsutil.LoadClientConfig(dir+"/client.pem", dir+"/client-key.pem", dir+"/ca.pem", "")
	if err != nil {
		t.Fatal(err)
	}

	echo := startEcho(t)
	defer echo.Close()

	srv := server.New(server.Options{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  sTLS,
		Token:      "s3cret",
		Logger:     discardLogger(),
	})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	// Client without the token must be rejected and stop (no reconnect loop).
	err = client.Run(ctx, client.Options{
		ServerAddr: srv.Addr().String(),
		LocalAddr:  echo.Addr().String(),
		TLSConfig:  cTLS,
		Logger:     discardLogger(),
	})
	var authErr *client.AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected AuthError, got %v", err)
	}
}
