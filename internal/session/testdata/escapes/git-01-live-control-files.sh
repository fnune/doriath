#!/bin/sh
# threat: make git on the desktop run a hook or a program named in config
# expect: held
# setup: live-repo

cd "{{LIVE_REPO}}" || exit 1
printf '#!/bin/sh\necho owned\n' > .git/hooks/pre-commit 2>/dev/null && { echo "ESCAPED: wrote a hook"; exit 1; }
printf '[core]\n\tfsmonitor = /tmp/x\n' >> .git/config 2>/dev/null && { echo "ESCAPED: changed .git/config"; exit 1; }
echo '* filter=x' > .git/info/attributes 2>/dev/null && { echo "ESCAPED: wrote .git/info"; exit 1; }
exit 0
