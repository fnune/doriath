#!/usr/bin/env bash
# Screenshots the approvals page with two pending requests from a scripted
# stand-in for an agent, in light and dark. Needs the dev shell for the
# binary, and shot-scraper with its browser (`shot-scraper install`).
# Usage: approvals-page.sh PATH-TO-DORIATH-BINARY OUTPUT-DIR
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
out=$(realpath -m "${2:?usage: approvals-page.sh PATH-TO-DORIATH-BINARY OUTPUT-DIR}")
root=${VISUALS_ROOT:-/tmp/doriath-visuals}
addr=127.0.0.1:7391

"$here/setup.sh" "$1" >/dev/null
mkdir -p "$out"

isolated() {
    env -i TERM=xterm-256color PATH="$PATH" bash --norc -c ". '$root/env.sh'; cd ~/acme-app; $*"
}

cleanup() { pkill -f "$root/" || true; pkill -f -- "web --listen $addr" || true; }
trap cleanup EXIT

isolated doriath run --profile my-app -- ./agent.sh >/dev/null 2>&1 &
isolated doriath web --listen "$addr" >/dev/null 2>&1 &

for _ in $(seq 40); do
    [ "$(isolated doriath approvals | grep -c 'my-app')" -ge 2 ] && break
    sleep 0.5
done

for _ in $(seq 40); do
    isolated doriath web open --listen "$addr" --print >/dev/null 2>&1 && break
    sleep 0.5
done

for theme in light dark; do
    link=$(isolated doriath web open --listen "$addr" --print | grep '^http')
    shot-scraper "$link" --output "$out/approvals-$theme.png" \
        --width 1200 --height 640 --retina --wait 1500 \
        --javascript "document.documentElement.dataset.theme = '$theme'; [...document.querySelectorAll('a.item')].find(a => a.textContent.includes('Merge a pull request')).click()"
done
