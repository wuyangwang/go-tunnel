// gotunnel-gencerts generates a self-signed private CA plus server and
// client certificates. Used both to provision certs/ and to generate
// PEM files that are embedded into a self-contained binary via
// go:embed (see internal/tlsutil/embedded).
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"gotunnel/internal/tlsutil"
)

func main() {
	var (
		dir = flag.String("dir", "certs", "output directory for generated PEM files")
		san = flag.String("san", "", "extra comma-separated SANs (DNS names or IPs) for the server certificate")
	)
	flag.Parse()

	var sans []string
	for _, s := range strings.Split(*san, ",") {
		if s = strings.TrimSpace(s); s != "" {
			sans = append(sans, s)
		}
	}

	if err := tlsutil.Generate(*dir, sans); err != nil {
		fmt.Fprintln(os.Stderr, "gencerts:", err)
		os.Exit(1)
	}
	fmt.Println("generated TLS material in", *dir)
}
