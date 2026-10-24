#!/bin/sh
# threat: move a guarded .git aside, or remove it, to get a plain one with writable hooks and config
# expect: held
# setup: live-repo

cd "{{LIVE_REPO}}" || exit 1
mv .git .git.moved 2>/dev/null && { echo "ESCAPED: renamed .git"; exit 1; }
mv .git/hooks .git/hooks.moved 2>/dev/null && { echo "ESCAPED: renamed .git/hooks"; exit 1; }
cp -a .git .git.copy 2>/dev/null
mv -T .git.copy .git 2>/dev/null && { echo "ESCAPED: replaced .git"; exit 1; }
rm -rf .git.copy
rm -rf .git 2>/dev/null
[ -d .git/hooks ] || { echo "ESCAPED: .git/hooks is gone"; exit 1; }
printf '#!/bin/sh\necho owned\n' > .git/hooks/pre-commit 2>/dev/null && { echo "ESCAPED: wrote a hook"; exit 1; }
printf '[core]\n\tfsmonitor = /tmp/x\n' >> .git/config 2>/dev/null && { echo "ESCAPED: changed .git/config"; exit 1; }
exit 0
