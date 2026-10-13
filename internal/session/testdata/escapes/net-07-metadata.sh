#!/bin/sh
# threat: reach a cloud metadata service or the local network through the proxy
# expect: held
# setup: rebinding

curl -fsS -m 5 -o /dev/null http://169.254.169.254/ 2>/dev/null && { echo "ESCAPED: metadata over HTTP"; exit 1; }
curl -fsS -m 5 -o /dev/null https://169.254.169.254/ 2>/dev/null && { echo "ESCAPED: metadata over a tunnel"; exit 1; }
curl -fsS -m 5 -o /dev/null https://rebinding.example/ 2>/dev/null && { echo "ESCAPED: an allowed name that resolves to the metadata address"; exit 1; }
exit 0
