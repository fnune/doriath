default:
    @just --list

# Copy the static bubblewrap from the dev shell, for bundled builds.
bundle:
    mkdir -p internal/bundle/assets
    install -m 0644 "${GIRDLE_STATIC_BWRAP:?enter the dev shell first: nix develop}" internal/bundle/assets/bwrap

build: bundle
    CGO_ENABLED=0 go build -tags bundled -o girdle ./cmd/girdle

fmt:
    gofumpt -w .
    prettier --write '**/*.md'

lint:
    golangci-lint run ./...

test:
    go test -race ./...

# Starts real jails. Set GIRDLE_TEST_NETWORK=1 to also pull a container image.
test-integration:
    go test -race -tags integration -count=1 ./internal/session/

# Searches for new inputs to each fuzz target. Their seeds already run with `just test`.
fuzz time="30s":
    #!/usr/bin/env bash
    set -euo pipefail
    for pkg in $(go list ./...); do
        for target in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true); do
            go test -run '^$' -fuzz "^${target}\$" -fuzztime {{time}} "$pkg"
        done
    done

vuln:
    govulncheck ./...

check:
    test -z "$(gofumpt -l .)" || (gofumpt -l . && exit 1)
    go vet ./...
    golangci-lint run ./...
    go test -race ./...

# Updates the vendor hash after go.mod changes.
vendor-hash:
    echo 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' > nix/vendor-hash
    nix build .#default 2>&1 | sed -n 's/.*got: *//p' | tr -d ' ' > nix/vendor-hash.new || true
    mv nix/vendor-hash.new nix/vendor-hash
    cat nix/vendor-hash
