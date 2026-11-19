#!/bin/sh
# threat: write hooks into the folder that core.hooksPath names inside the checkout, which git on the desktop runs
# expect: held
# setup: hooks-repo

cd "{{HOOKS_REPO}}" || exit 1
printf '#!/bin/sh\necho owned\n' > .githooks/pre-commit 2>/dev/null && { echo "ESCAPED: rewrote a hook in the hooksPath folder"; exit 1; }
printf '#!/bin/sh\necho owned\n' > .githooks/post-checkout 2>/dev/null && { echo "ESCAPED: added a hook to the hooksPath folder"; exit 1; }
mv .githooks .githooks.moved 2>/dev/null && { echo "ESCAPED: moved the hooksPath folder"; exit 1; }
exit 0
