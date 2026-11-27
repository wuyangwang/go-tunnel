# GoTunnel build targets. Requires Go.
MODULE   := gotunnel
BIN_DIR  := bin
EMBED    := internal/tlsutil/embedded

.PHONY: all build test vet fmt clean selfcontained

all: build

# Normal binaries (TLS certs provided at runtime or auto-generated).
build:
	go build -o $(BIN_DIR)/gotunnel-server ./cmd/server
	go build -o $(BIN_DIR)/gotunnel-client ./cmd/client

test:
	go test ./... -count=1

vet:
	go vet ./...

fmt:
	gofmt -l .

# Self-contained single binaries: generate certs, embed them via go:embed.
# WARNING: the built binaries contain private keys. Only distribute to
# yourself; do NOT publish. The generated PEMs are git-ignored.
# Windows client example: GOOS=windows go build -o $(BIN_DIR)/gotunnel-client.exe ./cmd/client
selfcontained:
	go run ./cmd/gencerts -dir $(EMBED)
	go build -o $(BIN_DIR)/gotunnel-server ./cmd/server
	go build -o $(BIN_DIR)/gotunnel-client ./cmd/client
	@echo "Built self-contained binaries in $(BIN_DIR)/ (contain embedded keys!)."

clean:
	rm -rf $(BIN_DIR)
	rm -f $(EMBED)/*.pem
