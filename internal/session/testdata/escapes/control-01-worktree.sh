#!/bin/sh
# threat: work in the mounted directory
# expect: works

echo hello > "$PWD/control-file" && [ "$(cat "$PWD/control-file")" = hello ] || { echo "ESCAPED: cannot write the worktree"; exit 1; }
