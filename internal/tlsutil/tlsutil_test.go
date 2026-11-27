package tlsutil

import (
	"crypto/tls"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPEMConstructors(t *testing.T) {
	dir := t.TempDir()
	if err := Generate(dir, nil); err != nil {
		t.Fatal(err)
	}

	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	caPEM := read(CAFile)

	serverTLS, err := ServerConfigFromPEM(read(ServerCertFile), read(ServerKeyFile), caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if serverTLS.ClientAuth.String() != "RequireAndVerifyClientCert" {
		t.Fatalf("client auth not required: %v", serverTLS.ClientAuth)
	}

	clientTLS, err := ClientConfigFromPEM(read(ClientCertFile), read(ClientKeyFile), caPEM, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(clientTLS.Certificates) != 1 || clientTLS.RootCAs == nil {
		t.Fatal("client config incomplete")
	}

	if _, err := ServerConfigFromPEM([]byte("junk"), []byte("junk"), caPEM); err == nil {
		t.Fatal("expected error for bad keypair")
	}
	if _, err := ClientConfigFromPEM(read(ClientCertFile), read(ClientKeyFile), []byte("nope"), ""); err == nil {
		t.Fatal("expected error for bad CA")
	}
}

func TestEmbeddedAbsentByDefault(t *testing.T) {
	// In a normal checkout no PEMs are committed in embedded/.
	if _, _, _, ok := EmbeddedServerCerts(); ok {
		t.Skip("embedded server certs present in this build")
	}
	if _, _, _, ok := EmbeddedClientCerts(); ok {
		t.Skip("embedded client certs present in this build")
	}
}

func TestTokenDerivedTLS(t *testing.T) {
	const token = "s3cret-token-for-test"
	sCfg, err := TokenServerConfig(token)
	if err != nil {
		t.Fatal(err)
	}
	cCfg, err := TokenClientConfig(token, "")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", sCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4)
				if _, err := io.ReadFull(c, buf); err == nil { // server handshake happens here
					_, _ = c.Write(buf)
				}
			}(c)
		}
	}()

	// Correct token: mutual TLS handshake + echo works.
	conn, err := tls.Dial("tcp", ln.Addr().String(), cCfg)
	if err != nil {
		t.Fatalf("dial with correct token: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if string(buf) != "ping" {
		t.Fatalf("echo got %q", buf)
	}

	// Wrong token: server cannot verify client cert; handshake/IO fails.
	badCfg, err := TokenClientConfig("wrong-token", "")
	if err != nil {
		t.Fatal(err)
	}
	bad, err := tls.Dial("tcp", ln.Addr().String(), badCfg)
	if err != nil {
		return // handshake rejected
	}
	defer bad.Close()
	_ = bad.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := bad.Write([]byte("ping")); err != nil {
		return
	}
	if _, err := io.ReadFull(bad, buf); err == nil {
		t.Fatal("expected failure with wrong token")
	}
}
