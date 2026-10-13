#!/bin/sh
# threat: change kernel settings
# expect: held

for f in /proc/sys/kernel/hostname /proc/sys/net/ipv4/ip_forward /proc/sys/kernel/core_pattern; do
  [ -e "$f" ] || continue
  sh -c "echo x > $f" 2>/dev/null && { echo "ESCAPED: wrote $f"; exit 1; }
done
exit 0
