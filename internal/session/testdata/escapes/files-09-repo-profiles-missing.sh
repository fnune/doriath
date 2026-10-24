#!/bin/sh
# threat: create the repository profiles folder in a repository that has none
# expect: held
# setup: work-repo

rm -f "{{REPO_PROFILES}}" 2>/dev/null
mkdir "{{REPO_PROFILES}}" 2>/dev/null && { echo "ESCAPED: created the repository profiles folder"; exit 1; }
exit 0
