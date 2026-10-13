#!/bin/sh
# threat: read system state, logs, other users' files or programs such as password managers
# expect: held

for d in /var/lib /var/log /opt /root /mnt /media /srv /boot; do
  [ -n "$(ls -A "$d" 2>/dev/null)" ] && { echo "ESCAPED: $d is not empty"; exit 1; }
done
exit 0
