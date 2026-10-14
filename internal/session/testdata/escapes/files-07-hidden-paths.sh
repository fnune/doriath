#!/bin/sh
# threat: read or replace files the profile hides inside a writable mount
# expect: held
# setup: hidden

[ -n "$(ls -A "{{WORK}}/hidden-dir")" ] && { echo "ESCAPED: the hidden directory lists $(ls -A "{{WORK}}/hidden-dir")"; exit 1; }
[ -s "{{WORK}}/.env" ] && { echo "ESCAPED: the hidden file reads $(cat "{{WORK}}/.env")"; exit 1; }
touch "{{WORK}}/hidden-dir/planted" 2>/dev/null && { echo "ESCAPED: wrote into the hidden directory"; exit 1; }
echo planted > "{{WORK}}/.env" 2>/dev/null && { echo "ESCAPED: wrote the hidden file"; exit 1; }
exit 0
