#!/bin/sh
# threat: forge identities by reading or writing the memory of girdle's init
# expect: held

for f in /proc/2/mem /proc/2/environ /proc/2/maps; do
  head -c 1 "$f" >/dev/null 2>&1 && { echo "ESCAPED: read $f"; exit 1; }
done
exit 0
