// Package tlsutil loads and generates TLS material for GoTunnel.
//
// GoTunnel uses mutual TLS: server and client both present certificates
// signed by a shared private CA. The generated server certificate is
// verified by chain-of-trust against that CA; hostname verification can
// additionally be requested with a server name.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// embedded holds optional build-time certificates. PEM files placed in
// internal/tlsutil/embedded before `go build` are compiled into the
// binary; `all:` also embeds dotfiles so an empty directory builds.
//
//	go run ./cmd/gencerts -dir internal/tlsutil/embedded
//	go build ./cmd/server ./cmd/client
//
// WARNING: any private key here ends up inside the built binary. Only
// use for binaries you build and distribute yourself; never for public
// releases. Generated PEM files are git-ignored.
//
//go:embed all:embedded
var embedded embed.FS

//go:generate go run gotunnel/cmd/gencerts -dir embedded

// EmbeddedServerCerts returns build-time embedded server material, if present.
func EmbeddedServerCerts() (certPEM, keyPEM, caPEM []byte, ok bool) {
	certPEM, _ = embedded.ReadFile("embedded/" + ServerCertFile)
	keyPEM, _ = embedded.ReadFile("embedded/" + ServerKeyFile)
	caPEM, _ = embedded.ReadFile("embedded/" + CAFile)
	return certPEM, keyPEM, caPEM, len(certPEM) > 0 && len(keyPEM) > 0 && len(caPEM) > 0
}

// EmbeddedClientCerts returns build-time embedded client material, if present.
func EmbeddedClientCerts() (certPEM, keyPEM, caPEM []byte, ok bool) {
	certPEM, _ = embedded.ReadFile("embedded/" + ClientCertFile)
	keyPEM, _ = embedded.ReadFile("embedded/" + ClientKeyFile)
	caPEM, _ = embedded.ReadFile("embedded/" + CAFile)
	return certPEM, keyPEM, caPEM, len(certPEM) > 0 && len(keyPEM) > 0 && len(caPEM) > 0
}

// TokenServerConfig builds a mutual-TLS server config whose CA, server
// and client credentials are derived deterministically from a shared
// secret. No certificate files are read or written; nothing is stored.
// Authorization reduces to "knows the token". TLS encryption and mutual
// authentication are still enforced. serverName, if set, enables
// hostname verification; generated server certs only cover localhost.
func TokenServerConfig(token string) (*tls.Config, error) {
	cfg, err := tokenConfig(token, "server", x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, err
	}
	cfg.ClientCAs = cfg.RootCAs
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.RootCAs = nil
	return cfg, nil
}

// TokenClientConfig is the client counterpart of TokenServerConfig.
func TokenClientConfig(token, serverName string) (*tls.Config, error) {
	cfg, err := tokenConfig(token, "client", x509.ExtKeyUsageClientAuth)
	if err != nil {
		return nil, err
	}
	cfg.ServerName = serverName
	cfg.InsecureSkipVerify = true //nolint:gosec // chain verified in VerifyConnection
	roots := cfg.RootCAs
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("tlsutil: server sent no certificate")
		}
		_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
			Roots:     roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSName:   serverName,
		})
		return err
	}
	return cfg, nil
}

// tokenConfig builds a tls.Config presenting `role`'s derived cert,
// signed by a CA derived from token, trusting that CA (in RootCAs;
// callers adjust fields).
func tokenConfig(token, role string, extKeyUsage x509.ExtKeyUsage) (*tls.Config, error) {
	if token == "" {
		return nil, errors.New("tlsutil: token-derived TLS requires a non-empty token")
	}
	caKey := deriveKey(token, "ca")
	caCertDER, err := selfSignedCA(caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, err
	}

	leafKey := deriveKey(token, role)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "GoTunnel " + role, Organization: []string{"GoTunnel"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{extKeyUsage},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, leafKey.Public(), caKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leaf.Raw},
			PrivateKey:  leafKey,
		}},
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}, nil
}

var (
	notBefore = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2199, 12, 31, 23, 59, 59, 0, time.UTC)
)

func deriveKey(secret, purpose string) ed25519.PrivateKey {
	h := sha256.New()
	h.Write([]byte("gotunnel/token-tls/v1/"))
	h.Write([]byte(purpose))
	h.Write([]byte{0})
	h.Write([]byte(secret))
	return ed25519.NewKeyFromSeed(h.Sum(nil)[:ed25519.SeedSize])
}

func selfSignedCA(key ed25519.PrivateKey) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "GoTunnel Token CA", Organization: []string{"GoTunnel"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
}

const (
	// File names used by Generate.
	CAFile         = "ca.pem"
	CAKeyFile      = "ca-key.pem"
	ServerCertFile = "server.pem"
	ServerKeyFile  = "server-key.pem"
	ClientCertFile = "client.pem"
	ClientKeyFile  = "client-key.pem"
)

// LoadServerConfig builds a mutual-TLS server config from PEM files.
func LoadServerConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: read server cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: read server key: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: read CA file: %w", err)
	}
	return ServerConfigFromPEM(certPEM, keyPEM, caPEM)
}

// ServerConfigFromPEM builds a mutual-TLS server config from PEM bytes
// (e.g. build-time embedded certificates).
func ServerConfigFromPEM(certPEM, keyPEM, caPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: load server keypair: %w", err)
	}
	pool, err := poolFromPEM(caPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// LoadClientConfig builds a mutual-TLS client config from PEM files.
// The server certificate is verified against the CA; if serverName is
// non-empty, hostname verification is enforced as well.
func LoadClientConfig(certFile, keyFile, caFile, serverName string) (*tls.Config, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: read client cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: read client key: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: read CA file: %w", err)
	}
	return ClientConfigFromPEM(certPEM, keyPEM, caPEM, serverName)
}

// ClientConfigFromPEM builds a mutual-TLS client config from PEM bytes
// (e.g. build-time embedded certificates).
func ClientConfigFromPEM(certPEM, keyPEM, caPEM []byte, serverName string) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: load client keypair: %w", err)
	}
	pool, err := poolFromPEM(caPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
		// Built-in verification cannot express "chain-only, hostname
		// optional", so verify manually against our private CA.
		InsecureSkipVerify: true, //nolint:gosec // chain verified in VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("tlsutil: server sent no certificate")
			}
			opts := x509.VerifyOptions{
				Roots:         pool,
				Intermediates: x509.NewCertPool(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				DNSName:       serverName,
			}
			for _, c := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(c)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		},
	}, nil
}

func poolFromPEM(pemBytes []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("tlsutil: no valid CA certificates in PEM")
	}
	return pool, nil
}

// Generate creates a fresh private CA plus server and client
// certificates in dir (mode 0700; keys are written 0600). extraSANs are
// additional DNS names or IP addresses for the server certificate.
// Existing files are not overwritten.
func Generate(dir string, extraSANs []string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "GoTunnel CA", Organization: []string{"GoTunnel"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}

	// Server certificate.
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	dnsNames := []string{"localhost"}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	for _, name := range extraSANs {
		if ip := net.ParseIP(name); ip != nil {
			ips = append(ips, ip)
		} else if name != "" {
			dnsNames = append(dnsNames, name)
		}
	}
	serverTmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: "GoTunnel Server", Organization: []string{"GoTunnel"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	// Client certificate.
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	clientTmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: "GoTunnel Client", Organization: []string{"GoTunnel"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	files := []struct {
		name    string
		data    []byte
		mode    os.FileMode
		pemType string
	}{
		{CAFile, caDER, 0o644, "CERTIFICATE"},
		{ServerCertFile, serverDER, 0o644, "CERTIFICATE"},
		{ClientCertFile, clientDER, 0o644, "CERTIFICATE"},
	}
	keys := []struct {
		name string
		key  *ecdsa.PrivateKey
		mode os.FileMode
	}{
		{CAKeyFile, caKey, 0o600},
		{ServerKeyFile, serverKey, 0o600},
		{ClientKeyFile, clientKey, 0o600},
	}

	for _, f := range files {
		if err := writePEMIfAbsent(filepath.Join(dir, f.name), f.pemType, f.data, f.mode); err != nil {
			return err
		}
	}
	for _, k := range keys {
		der, err := x509.MarshalPKCS8PrivateKey(k.key)
		if err != nil {
			return err
		}
		if err := writePEMIfAbsent(filepath.Join(dir, k.name), "PRIVATE KEY", der, k.mode); err != nil {
			return err
		}
	}
	return nil
}

func writePEMIfAbsent(path, pemType string, der []byte, mode os.FileMode) error {
	if _, err := os.Stat(path); err == nil {
		return nil // never overwrite existing key material
	}
	block := &pem.Block{Type: pemType, Bytes: der}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), mode); err != nil {
		return fmt.Errorf("tlsutil: write %s: %w", path, err)
	}
	return nil
}

func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		// Fall back to a time-based serial; serial uniqueness is not
		// a security requirement here.
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}
