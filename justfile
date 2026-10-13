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

# Gremlins sets its test timeout from the coverage run, so a cached run would
# time out every mutant. The nix shell's long TMPDIR pushes the tests' unix
# socket paths past the kernel's limit.

# Mutation testing of the security-critical packages. Slow: run it now and then, not in CI.
mutate:
    for pkg in seccomp jail proxy containers profile approval ca landlock; do \
        TMPDIR=/tmp GOFLAGS=-count=1 go run github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0 unleash \
            --invert-logical --invert-bitwise --invert-loopctrl --timeout-coefficient 30 --output-statuses lt \
            ./internal/$pkg; \
    done

# Updates the vendor hash after go.mod changes.
vendor-hash:
    echo 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' > nix/vendor-hash
    nix build .#default 2>&1 | sed -n 's/.*got: *//p' | tr -d ' ' > nix/vendor-hash.new || true
    mv nix/vendor-hash.new nix/vendor-hash
    cat nix/vendor-hash
