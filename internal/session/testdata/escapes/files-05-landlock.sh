#!/bin/sh
# threat: write to an empty system directory that the jail mounts writable at the file system level
# expect: held

for d in /var /opt /mnt; do
  [ -d "$d" ] || continue
  touch "$d/girdle-escape" 2>/dev/null && { echo "ESCAPED: wrote into $d despite Landlock"; exit 1; }
done
exit 0
