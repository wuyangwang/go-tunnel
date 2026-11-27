// gotunnel-client: GoTunnel PC client (Windows).
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gotunnel/internal/client"
	"gotunnel/internal/daemon"
	"gotunnel/internal/protocol"
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

func certFlagsSet() bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "cert" || f.Name == "key" || f.Name == "ca" {
			set = true
		}
	})
	return set
}

func embeddedClientCertsPresent() bool {
	_, _, _, ok := tlsutil.EmbeddedClientCerts()
	return ok
}

func clientCertsPresent() bool {
	return fileExists(certDir+"/"+tlsutil.ClientCertFile) &&
		fileExists(certDir+"/"+tlsutil.ClientKeyFile) &&
		fileExists(certDir+"/"+tlsutil.CAFile)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	var (
		serverAddr     = flag.String("server", "", "VPS address host:port (required)")
		port           = flag.Int("port", protocol.DefaultClientPort, "local proxy port to forward to (Charles)")
		local          = flag.String("local", "", "local proxy address to forward to (overrides -port; default 127.0.0.1:<port>)")
		cert           = flag.String("cert", certDir+"/"+tlsutil.ClientCertFile, "client certificate PEM")
		key            = flag.String("key", certDir+"/"+tlsutil.ClientKeyFile, "client private key PEM")
		ca             = flag.String("ca", certDir+"/"+tlsutil.CAFile, "CA PEM used to verify the server certificate")
		token          = flag.String("token", os.Getenv("GOTUNNEL_TOKEN"), "shared token matching the server (env GOTUNNEL_TOKEN); when no certificate files are given it also derives mutual-TLS certificates in memory")
		serverName     = flag.String("server-name", "", "expected server name for TLS hostname verification (default: verify chain only)")
		reconnectDelay = flag.Duration("reconnect-delay", time.Second, "delay between reconnect attempts")
		dialTimeout    = flag.Duration("dial-timeout", 5*time.Second, "dial timeout for server and local proxy")
	)
	if len(os.Args) > 1 && daemon.IsCommand(os.Args[1]) {
		runDaemon("gotunnel-client", os.Args[1], os.Args[2:])
		return
	}
	flag.Parse()

	if *serverAddr == "" {
		fmt.Fprintln(os.Stderr, "gotunnel-client: -server is required (e.g. -server YOUR_VPS_IP:4567)")
		flag.Usage()
		os.Exit(2)
	}

	localAddr := *local
	if localAddr == "" {
		localAddr = fmt.Sprintf("127.0.0.1:%d", *port)
	}

	var tlsConfig *tls.Config
	var err error
	switch {
	case certFlagsSet():
		// Explicit certificate files take precedence.
		tlsConfig, err = tlsutil.LoadClientConfig(*cert, *key, *ca, *serverName)
	case embeddedClientCertsPresent():
		// Self-contained binary built with embedded certificates.
		certPEM, keyPEM, caPEM, _ := tlsutil.EmbeddedClientCerts()
		tlsConfig, err = tlsutil.ClientConfigFromPEM(certPEM, keyPEM, caPEM, *serverName)
		log.Info("using build-time embedded TLS certificates")
	case clientCertsPresent():
		// Previously provisioned certs/ on disk; use them (plus optional token).
		tlsConfig, err = tlsutil.LoadClientConfig(*cert, *key, *ca, *serverName)
	case *token != "":
		// No certificate files anywhere; derive mutual TLS from the token.
		tlsConfig, err = tlsutil.TokenClientConfig(*token, *serverName)
		log.Info("using token-derived TLS (no certificate files)")
	default:
		tlsConfig, err = tlsutil.LoadClientConfig(*cert, *key, *ca, *serverName)
	}
	if err != nil {
		log.Error("load TLS config", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = client.Run(ctx, client.Options{
		ServerAddr:     *serverAddr,
		LocalAddr:      localAddr,
		TLSConfig:      tlsConfig,
		Token:          *token,
		ReconnectDelay: *reconnectDelay,
		DialTimeout:    *dialTimeout,
		Logger:         log,
	})
	if err != nil {
		log.Error("client exited", "err", err)
		os.Exit(1)
	}
}
