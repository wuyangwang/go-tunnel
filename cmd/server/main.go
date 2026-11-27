// gotunnel-server: GoTunnel VPS server.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"gotunnel/internal/daemon"
	"gotunnel/internal/protocol"
	"gotunnel/internal/server"
	"gotunnel/internal/tlsutil"
)

const certDir = "certs"

func runDaemon(name, cmd string, args []string) {
	m, err := daemon.New(name)
	if err == nil {
		err = m.Handle(cmd, args)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, name+":", err)
		os.Exit(1)
	}
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	var (
		listen     = flag.String("listen", "", "listen address (overrides -port)")
		port       = flag.Int("port", protocol.DefaultServerPort, "listen port")
		cert       = flag.String("cert", certDir+"/"+tlsutil.ServerCertFile, "server certificate PEM")
		key        = flag.String("key", certDir+"/"+tlsutil.ServerKeyFile, "server private key PEM")
		ca         = flag.String("ca", certDir+"/"+tlsutil.CAFile, "CA PEM used to verify client certificates")
		token      = flag.String("token", os.Getenv("GOTUNNEL_TOKEN"), "shared token (env GOTUNNEL_TOKEN); required from clients, and when no certificate files are given it also derives mutual-TLS certificates in memory")
		maxStreams = flag.Int("max-streams", server.DefaultMaxStreams, "max concurrent proxied connections per client session")
		initCerts  = flag.String("init-certs", "", "generate CA + server/client certificates into this directory and exit")
		san        = flag.String("san", "", "extra comma-separated SANs (DNS names or IPs) for generated server certificate")
	)
	if len(os.Args) > 1 && daemon.IsCommand(os.Args[1]) {
		runDaemon("gotunnel-server", os.Args[1], os.Args[2:])
		return
	}
	flag.Parse()

	if *initCerts != "" {
		if err := generateCerts(*initCerts, *san); err != nil {
			log.Error("certificate generation failed", "err", err)
			os.Exit(1)
		}
		return
	}

	listenAddr := *listen
	if listenAddr == "" {
		listenAddr = fmt.Sprintf("0.0.0.0:%d", *port)
	}

	var tlsConfig *tls.Config
	var err error
	switch {
	case certFlagsSet():
		// Explicit certificate files take precedence.
		tlsConfig, err = tlsutil.LoadServerConfig(*cert, *key, *ca)
	case embeddedServerCertsPresent():
		// Self-contained binary built with embedded certificates.
		certPEM, keyPEM, caPEM, _ := tlsutil.EmbeddedServerCerts()
		tlsConfig, err = tlsutil.ServerConfigFromPEM(certPEM, keyPEM, caPEM)
		log.Info("using build-time embedded TLS certificates")
	case serverCertsPresent():
		// Previously generated certs/ on disk; use them (plus optional token).
		tlsConfig, err = tlsutil.LoadServerConfig(*cert, *key, *ca)
	case *token != "":
		// No certificate files anywhere; derive mutual TLS from the token.
		tlsConfig, err = tlsutil.TokenServerConfig(*token)
		log.Info("using token-derived TLS (no certificate files)")
	default:
		// Auto-generate a certificate directory on first run.
		if err := ensureCerts(certDir, *san, log); err != nil {
			log.Error("certificate setup failed", "err", err)
			os.Exit(1)
		}
		tlsConfig, err = tlsutil.LoadServerConfig(*cert, *key, *ca)
	}
	if err != nil {
		log.Error("load TLS config", "err", err)
		os.Exit(1)
	}

	srv := server.New(server.Options{
		ListenAddr: listenAddr,
		TLSConfig:  tlsConfig,
		Token:      *token,
		MaxStreams: *maxStreams,
		Logger:     log,
	})
	if err := srv.Listen(); err != nil {
		log.Error("listen failed", "addr", listenAddr, "err", err)
		os.Exit(1)
	}
	log.Info("gotunnel-server listening", "addr", srv.Addr().String(), "max_streams", *maxStreams)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ctx) }()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
		_ = srv.Close()
		<-errCh
	case err := <-errCh:
		if err != nil {
			log.Error("serve failed", "err", err)
			os.Exit(1)
		}
	}
}

func embeddedServerCertsPresent() bool {
	_, _, _, ok := tlsutil.EmbeddedServerCerts()
	return ok
}

func serverCertsPresent() bool {
	return fileExists(certDir+"/"+tlsutil.ServerCertFile) &&
		fileExists(certDir+"/"+tlsutil.ServerKeyFile) &&
		fileExists(certDir+"/"+tlsutil.CAFile)
}

func certFlagsSet() bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "cert" || f.Name == "key" || f.Name == "ca" {
			set = true
		}
	})
	return set
}

func ensureCerts(dir, san string, log *slog.Logger) error {
	if fileExists(dir+"/"+tlsutil.ServerCertFile) &&
		fileExists(dir+"/"+tlsutil.ServerKeyFile) &&
		fileExists(dir+"/"+tlsutil.CAFile) {
		return nil
	}
	if err := generateCerts(dir, san); err != nil {
		return err
	}
	log.Info("generated TLS certificates", "dir", dir)
	log.Info("copy these files to the client machine",
		"files", strings.Join([]string{
			dir + "/" + tlsutil.CAFile,
			dir + "/" + tlsutil.ClientCertFile,
			dir + "/" + tlsutil.ClientKeyFile,
		}, ", "))
	return nil
}

func generateCerts(dir, san string) error {
	var sans []string
	for _, s := range strings.Split(san, ",") {
		if s = strings.TrimSpace(s); s != "" {
			sans = append(sans, s)
		}
	}
	return tlsutil.Generate(dir, sans)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
