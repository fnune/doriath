#!/bin/sh
PATH=/run/doriath-bin:$PATH
held() { curl -sS -m 300 -o /dev/null "$@" 2>/dev/null & sleep 0.4; }

doriath describe "Ship the v1.4 release of acme/app" >/dev/null
doriath request host sentry.io --reason "Upload the source maps of the release" >/dev/null
doriath request read ~/Documents/acme --reason "Follow the release checklist" >/dev/null
sleep 2
held -X PUT -H "Content-Type: application/json" -d '{"merge_method":"squash"}' https://api.github.com/repos/acme/app/pulls/42/merge
held -X POST -H "Content-Type: application/json" \
    -d '{"query":"mutation { requestReviewsByLogin(input: {pullRequestId: \"PR_kwDOAcme42\", userLogins: [\"ada\", \"grace\"]}) { clientMutationId } }"}' \
    https://api.github.com/graphql
held -X POST -H "Content-Type: application/json" -d '{"tag_name":"v1.4.0","name":"v1.4.0"}' https://api.github.com/repos/acme/app/releases
held https://api.acme.test/v1/releases
doriath request forward 5173 --reason "Preview the release notes page" >/dev/null
doriath request write ~/notes --reason "Tick the done items in the release checklist" >/dev/null
sleep 600
