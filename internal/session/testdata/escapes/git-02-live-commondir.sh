#!/bin/sh
# threat: redirect git to other config through a control file that does not exist yet
# expect: held
# setup: live-repo

cd "{{LIVE_REPO}}" || exit 1
echo /tmp/elsewhere > .git/commondir 2>/dev/null && { echo "ESCAPED: wrote .git/commondir"; exit 1; }
printf '[core]\n\thooksPath = /tmp\n' > .git/config.worktree 2>/dev/null && { echo "ESCAPED: wrote .git/config.worktree"; exit 1; }
echo /tmp/objects > .git/objects/info/alternates 2>/dev/null && { echo "ESCAPED: wrote .git/objects/info/alternates"; exit 1; }
git status >/dev/null 2>&1 || { echo "git no longer works with the placeholders"; exit 1; }
exit 0
