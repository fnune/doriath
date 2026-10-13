#!/bin/sh
# threat: read files elsewhere in your home directory, such as keys and tokens
# expect: held

[ -e "{{SECRET_FILE}}" ] && { echo "ESCAPED: $(cat "{{SECRET_FILE}}")"; exit 1; }
for f in "$HOME/.ssh/id_ed25519" "$HOME/.config/gh/hosts.yml" "$HOME/.aws/credentials" "$HOME/.netrc"; do
  [ -r "$f" ] && { echo "ESCAPED: $f is readable"; exit 1; }
done
exit 0
