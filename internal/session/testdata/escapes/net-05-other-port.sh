#!/bin/sh
# threat: reach an allowed host on a port other than 443
# expect: held

curl -fsS -m 5 -o /dev/null https://example.com:8443/ 2>/dev/null && { echo "ESCAPED: reached port 8443"; exit 1; }
exit 0
