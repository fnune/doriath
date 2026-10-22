#!/bin/sh
# threat: read the credential the proxy adds to requests
# expect: held

# Built at run time, so this script's own text does not match.
token="real"; token="$token-token"
env | grep -q "$token" && { echo "ESCAPED: token in the environment"; exit 1; }
grep -rqs "$token" /run/doriath "$HOME" /tmp 2>/dev/null && { echo "ESCAPED: token in a file"; exit 1; }
exit 0
