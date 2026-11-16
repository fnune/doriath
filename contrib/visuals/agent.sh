#!/bin/sh
curl -sS -m 300 -o /dev/null -X PUT -H "Content-Type: application/json" \
    -d '{"merge_method":"squash"}' https://api.github.com/repos/acme/app/pulls/42/merge 2>/dev/null &
sleep 1
curl -sS -m 300 -o /dev/null https://api.acme.test/v1/releases 2>/dev/null &
wait
