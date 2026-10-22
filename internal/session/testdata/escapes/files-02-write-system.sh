#!/bin/sh
# threat: change programs or configuration the desktop runs
# expect: held

for d in /etc /usr /usr/bin /nix/store /bin; do
  [ -d "$d" ] || continue
  touch "$d/doriath-escape" 2>/dev/null && { echo "ESCAPED: wrote into $d"; exit 1; }
done
exit 0
