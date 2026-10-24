#!/bin/sh
# threat: plant config, hooks, a commondir or a merge resolution that host git uses, or corrupt history in place, through a repository store [vcs] store makes writable
# expect: held
# setup: store-repo

R="{{STORE_REPO}}"
touch "$R/.git/objects/probe" || { echo "the store is not writable, so this test checks nothing"; exit 1; }
for f in "$R/.git/commondir" "$R/.git/modules/lib/commondir"; do
  echo /tmp/elsewhere > "$f" 2>/dev/null || continue
  for _ in $(seq 50); do [ -e "$f" ] || break; sleep 0.02; done
  [ -e "$f" ] && { echo "ESCAPED: $f stayed"; exit 1; }
done
for f in "$R/.git/config.worktree" "$R/.git/hooks/post-checkout" "$R/.git/info/attributes" "$R/.git/modules/lib/hooks/post-checkout"; do
  echo planted > "$f" 2>/dev/null && { echo "ESCAPED: wrote $f"; exit 1; }
done
echo '[core] fsmonitor = /tmp/x' >> "$R/.git/config" 2>/dev/null && { echo "ESCAPED: wrote .git/config"; exit 1; }
echo '[core] fsmonitor = /tmp/x' >> "$R/.git/modules/lib/config" 2>/dev/null && { echo "ESCAPED: wrote a submodule config"; exit 1; }
mkdir "$R/.git/rr-cache/planted" 2>/dev/null && { echo "ESCAPED: planted a rerere resolution"; exit 1; }
echo /tmp >> "$R/.git/objects/info/alternates" 2>/dev/null && { echo "ESCAPED: pointed host git at other objects"; exit 1; }
pack=$(ls "$R"/.git/objects/pack/*.pack 2>/dev/null | head -1)
[ -n "$pack" ] || { echo "the repository has no pack, so this test checks nothing"; exit 1; }
chmod u+w "$pack" 2>/dev/null; echo corrupt >> "$pack" 2>/dev/null && { echo "ESCAPED: rewrote a pack and its backup"; exit 1; }
rm -f "$pack" 2>/dev/null; [ -e "$pack" ] || { echo "ESCAPED: removed a pack"; exit 1; }
exit 0
