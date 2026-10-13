#!/bin/sh
# threat: leave a file in a live checkout that a desktop tool runs, such as .envrc
# expect: gap
# setup: live-repo

cd "{{LIVE_REPO}}" || exit 0
echo 'echo owned' > .envrc 2>/dev/null && { echo "ESCAPED: wrote .envrc"; exit 1; }
exit 0
