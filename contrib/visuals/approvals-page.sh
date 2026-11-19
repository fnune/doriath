#!/usr/bin/env bash
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
out=$(realpath -m "${2:?usage: approvals-page.sh PATH-TO-DORIATH-BINARY OUTPUT-DIR}")
root=${VISUALS_ROOT:-/tmp/doriath-visuals}
addr=127.0.0.1:7391

"$here/setup.sh" "$1" >/dev/null
mkdir -p "$out"

isolated() {
    env -i TERM=xterm-256color PATH="$PATH" bash --norc -c ". '$root/env.sh'; cd ~/acme-app; $(printf '%q ' "$@")"
}

cleanup() { pkill -f "$root/" || true; pkill -f -- "web --listen $addr" || true; }
trap cleanup EXIT

isolated doriath run --profile my-app -- ./agent.sh >/dev/null 2>&1 &
isolated doriath run --profile acme-infra -- ./infra-agent.sh >/dev/null 2>&1 &
isolated doriath web --listen "$addr" >/dev/null 2>&1 &

waiting() { isolated doriath approvals | grep -c -E 'my-app|acme-infra' || true; }
answer() {
    for _ in $(seq 40); do
        id=$(isolated doriath approvals | grep -F "$1" | grep -o -E '^\s*[a-z0-9]{5}' | tr -d ' ' | head -1 || true)
        [ -n "$id" ] && break
        sleep 0.5
    done
    isolated doriath approvals "${@:2}" "$id" >/dev/null
}

answer sentry.io deny --reason "Upload the source maps from CI"
answer Documents/acme allow
for _ in $(seq 40); do
    [ "$(waiting)" -ge 10 ] && break
    sleep 0.5
done

for _ in $(seq 40); do
    isolated doriath web open --listen "$addr" --print >/dev/null 2>&1 && break
    sleep 0.5
done

for theme in light dark; do
    link=$(isolated doriath web open --listen "$addr" --print | grep '^http')
    shot-scraper "$link" --output "$out/approvals-$theme.png" \
        --width 1200 --height 1000 --retina --wait 1500 \
        --javascript "document.documentElement.dataset.theme = '$theme'; [...document.querySelectorAll('a.item')].find(a => a.textContent.includes('Merge pull request')).click(); new Promise(done => setTimeout(done, 600))"
done
