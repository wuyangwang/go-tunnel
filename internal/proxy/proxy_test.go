package proxy

import (
	"bufio"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestServeDirectHTTP(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		line, _ := r.ReadString('\n')
		if !strings.Contains(line, "GET /path HTTP/1.1") {
			return
		}
		for {
			l, _ := r.ReadString('\n')
			if l == "\r\n" || l == "\n" {
				break
			}
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	}()

	client, server := net.Pipe()
	defer client.Close()
	go ServeDirect(server, Options{DialTimeout: 2 * time.Second, Logger: discardLogger()})

	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	req := "GET http://" + target.Addr().String() + "/path HTTP/1.1\r\nHost: " + target.Addr().String() + "\r\n\r\n"
	if _, err := io.WriteString(client, req); err != nil {
		t.Fatal(err)
	}
	resp, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "200") {
		t.Fatalf("got %q", resp)
	}
}

func TestServeDirectConnect(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err == nil {
			_, _ = c.Write(buf)
		}
	}()

	client, server := net.Pipe()
	defer client.Close()
	go ServeDirect(server, Options{DialTimeout: 2 * time.Second, Logger: discardLogger()})

	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	req := "CONNECT " + target.Addr().String() + " HTTP/1.1\r\nHost: " + target.Addr().String() + "\r\n\r\n"
	if _, err := io.WriteString(client, req); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("CONNECT got %q", line)
	}
	if _, err := io.WriteString(client, "ping"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("tunneled data %q", buf)
	}
}

func TestServeDirectUnauthorized(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go ServeDirect(server, Options{
		DialTimeout: 2 * time.Second,
		Logger:      discardLogger(),
		Authorize:   func(map[string]string) bool { return false },
	})

	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(client, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "407") {
		t.Fatalf("got %q", line)
	}
}

func TestAuthorizeBasicToken(t *testing.T) {
	auth := AuthorizeBasicToken("s3cret")
	if auth == nil {
		t.Fatal("nil auth")
	}
	good := map[string]string{
		"proxy-authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("user:s3cret")),
	}
	if !auth(good) {
		t.Fatal("expected authorize success")
	}
	bad := map[string]string{"proxy-authorization": "Basic dXNlcjp3cm9uZw=="}
	if auth(bad) {
		t.Fatal("expected authorize failure")
	}
	if auth(map[string]string{}) {
		t.Fatal("expected missing auth to fail")
	}
}
