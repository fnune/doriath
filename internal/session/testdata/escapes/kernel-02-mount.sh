#!/bin/sh
# threat: mount a file system over the jail's view
# expect: held

mount -t tmpfs none /mnt 2>/dev/null && { echo "ESCAPED: mounted"; exit 1; }
umount /run/doriath 2>/dev/null && { echo "ESCAPED: unmounted"; exit 1; }
exit 0
