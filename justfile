default:
    @just --list

# Copy the static bubblewrap from the dev shell, for bundled builds.
bundle:
    mkdir -p internal/bundle/assets
    install -m 0644 "${DORIATH_STATIC_BWRAP:?enter the dev shell first: nix develop}" internal/bundle/assets/bwrap

build: bundle
    CGO_ENABLED=0 go build -tags bundled -o doriath ./cmd/doriath

fmt:
    gofumpt -w .
    prettier --write '**/*.{md,mdx}'

lint:
    golangci-lint run ./...

test:
    go test -race ./...

# Starts real jails. Set DORIATH_TEST_NETWORK=1 to also pull a container image.
test-integration:
    go test -race -tags integration -count=1 ./internal/session/

floci_image := "docker.io/floci/floci:2.3.0"

# Runs the AWS CLI through doriath against floci, an AWS emulator that checks
# each signature with its own code. Needs podman. floci uses the host's
# network, because rootless podman cannot always make one of its own.
test-floci:
    #!/usr/bin/env bash
    set -euo pipefail
    name="doriath-floci-$$"
    podman run -d --rm --name "$name" --network host -e FLOCI_AUTH_VALIDATE_SIGNATURES=true {{floci_image}} >/dev/null
    trap 'podman stop -t 2 "$name" >/dev/null' EXIT
    for _ in $(seq 50); do curl -fs -o /dev/null http://127.0.0.1:4566/_floci/health && break; sleep 0.2; done
    FLOCI_URL=http://127.0.0.1:4566 go test -race -tags integration -count=1 -run 'TestAWS' ./internal/session/

# Searches for new inputs to each fuzz target. Their seeds already run with `just test`.
fuzz time="30s":
    #!/usr/bin/env bash
    set -euo pipefail
    for pkg in $(go list ./...); do
        for target in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true); do
            go test -run '^$' -fuzz "^${target}\$" -fuzztime {{time}} "$pkg"
        done
    done

# Fixed in Go 1.26.10: empty this once the flake has it.
vuln_known := ""

# Fails on any vulnerability doriath calls that vuln_known does not list.
vuln:
    #!/usr/bin/env bash
    set -uo pipefail
    out=$(govulncheck ./...)
    status=$?
    if [ "$status" -ne 0 ] && [ "$status" -ne 3 ]; then
        printf '%s\n' "$out"
        exit "$status"
    fi
    new=$(printf '%s\n' "$out" | sed -n 's/^Vulnerability #[0-9]*: \(GO-[0-9-]*\)$/\1/p' | grep -vxF -f <(tr ' ' '\n' <<< "{{vuln_known}}") || true)
    if [ -n "$new" ]; then
        printf '%s\n' "$out"
        echo "New vulnerabilities: $new"
        exit 1
    fi

check:
    test -z "$(gofumpt -l .)" || (gofumpt -l . && exit 1)
    prettier --check '**/*.{md,mdx}'
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

# Refresh the hash of the site's npm dependencies after a change to site/package-lock.json.
site-npm-hash:
    echo 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' > nix/site-npm-hash
    nix build .#site 2>&1 | sed -n 's/.*got: *//p' | tr -d ' ' > nix/site-npm-hash.new || true
    mv nix/site-npm-hash.new nix/site-npm-hash
    cat nix/site-npm-hash

# The documentation site, at http://localhost:4321.
site-dev:
    cd site && npm ci && npm run dev

site-build:
    cd site && npm ci && npm run build

# Screenshots the approvals page with made-up data, in light and dark. Runs a
# real jail against a throwaway home, and needs `shot-scraper install` once.
visuals: build
    nix shell nixpkgs#shot-scraper nixpkgs#oxipng --command contrib/visuals/approvals-page.sh ./doriath site/public/visuals
    nix shell nixpkgs#oxipng --command oxipng --quiet --opt 4 --strip safe site/public/visuals/*.png
