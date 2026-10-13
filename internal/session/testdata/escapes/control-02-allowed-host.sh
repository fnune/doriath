#!/bin/sh
# threat: reach an allowed host through the proxy
# expect: works

code=$(curl -sS -m 10 -o /dev/null -w '%{http_code}' https://example.com/control)
[ "$code" = 200 ] || { echo "ESCAPED: allowed host gave $code"; exit 1; }
