#!/bin/sh
# threat: reach a host the profile does not allow
# expect: held

curl -fsS -m 5 -o /dev/null https://evil.example/ 2>/dev/null && { echo "ESCAPED: reached evil.example"; exit 1; }
curl -fsS -m 5 -o /dev/null http://evil.example/ 2>/dev/null && { echo "ESCAPED: reached evil.example over HTTP"; exit 1; }
exit 0
