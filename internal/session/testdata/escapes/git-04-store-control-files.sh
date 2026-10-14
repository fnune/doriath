#!/bin/sh
# threat: plant config, hooks, a commondir or a merge resolution that host git uses, through a repository store the vcs module makes writable
# expect: held
# setup: store-repo

R="{{STORE_REPO}}"
touch "$R/.git/objects/probe" || { echo "the store is not writable, so this test checks nothing"; exit 1; }
for f in "$R/.git/commondir" "$R/.git/config.worktree" "$R/.git/hooks/post-checkout" "$R/.git/info/attributes" \
  "$R/.git/modules/lib/commondir" "$R/.git/modules/lib/hooks/post-checkout"; do
  echo planted > "$f" 2>/dev/null && { echo "ESCAPED: wrote $f"; exit 1; }
done
echo '[core] fsmonitor = /tmp/x' >> "$R/.git/config" 2>/dev/null && { echo "ESCAPED: wrote .git/config"; exit 1; }
echo '[core] fsmonitor = /tmp/x' >> "$R/.git/modules/lib/config" 2>/dev/null && { echo "ESCAPED: wrote a submodule config"; exit 1; }
mkdir "$R/.git/rebase-merge" 2>/dev/null && { echo "ESCAPED: planted rebase state"; exit 1; }
mkdir "$R/.git/rr-cache/planted" 2>/dev/null && { echo "ESCAPED: planted a rerere resolution"; exit 1; }
exit 0
