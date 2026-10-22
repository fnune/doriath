#!/bin/sh
# threat: get write access, through doriath request write, to something the profile keeps read-only, hidden or out of sight
# expect: held

G=/run/doriath-bin/doriath
ln -s "{{HOME}}" "{{WORK}}/to-home" 2>/dev/null
for p in "{{WORK}}/to-home" "{{HOME}}" / /etc /run/doriath /proc/self /nix/store "{{WORK}}/.git/config" "{{HOME}}/invisible" "{{HOME}}/.ssh" "{{HOME}}/.claude" /var/tmp/x; do
  out=$($G request write "$p" 2>&1) && { echo "ESCAPED: $p: $out"; exit 1; }
  case "$out" in
    *"nobody decided"*) echo "ESCAPED: $p reached an approval prompt"; exit 1 ;;
    *"doriath: request: $p"*) ;;
    *) echo "the request for $p failed for another reason, so this test checks nothing: $out"; exit 1 ;;
  esac
done
exit 0
