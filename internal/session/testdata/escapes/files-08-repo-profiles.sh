#!/bin/sh
# threat: change the repository profiles that the next session loads
# expect: held
# setup: repo-profiles

echo '[egress]' > "{{REPO_PROFILES}}/dev.toml" 2>/dev/null && { echo "ESCAPED: changed a repository profile"; exit 1; }
echo '[egress]' > "{{REPO_PROFILES}}/new.toml" 2>/dev/null && { echo "ESCAPED: added a repository profile"; exit 1; }
mv "{{REPO_PROFILES}}" "{{REPO_PROFILES}}.old" 2>/dev/null && { echo "ESCAPED: moved the repository profiles away"; exit 1; }
exit 0
