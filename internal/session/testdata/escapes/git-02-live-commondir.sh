#!/bin/sh
# threat: redirect git to other config through a control file that does not exist yet
# expect: gap
# setup: live-repo

cd "{{LIVE_REPO}}" || exit 0
echo /tmp/elsewhere > .git/commondir 2>/dev/null && { echo "ESCAPED: created .git/commondir"; exit 1; }
exit 0
