#!/bin/sh
# threat: read, replace or create files the profile hides inside a writable mount
# expect: held
# setup: hidden

[ -n "$(ls -A "{{WORK}}/hidden-dir")" ] && { echo "ESCAPED: the hidden directory lists $(ls -A "{{WORK}}/hidden-dir")"; exit 1; }
[ -s "{{WORK}}/.env" ] && { echo "ESCAPED: the hidden file reads $(cat "{{WORK}}/.env")"; exit 1; }
touch "{{WORK}}/hidden-dir/planted" 2>/dev/null && { echo "ESCAPED: wrote into the hidden directory"; exit 1; }
echo planted > "{{WORK}}/.env" 2>/dev/null && { echo "ESCAPED: wrote the hidden file"; exit 1; }
echo planted > "{{WORK}}/.envrc" 2>/dev/null && { echo "ESCAPED: created a hidden file that did not exist"; exit 1; }
rm -f "{{WORK}}/.envrc" 2>/dev/null; mkdir "{{WORK}}/.envrc" 2>/dev/null && { echo "ESCAPED: created a hidden path as a directory"; exit 1; }
exit 0
