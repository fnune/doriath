#!/bin/sh
# threat: approve its own held requests, or find the socket where decisions are made
# expect: held

uid=$(id -u)
[ -e "/run/user/$uid/girdle" ] && { echo "ESCAPED: the host's session directory is visible"; exit 1; }
python3 - <<'PY'
import json, os, socket, sys
def ask(method):
    s = socket.socket(socket.AF_UNIX)
    s.connect(os.environ["GIRDLE_BROKER"])
    s.sendall(json.dumps({"method": method, "params": {"id": "x", "decision": {"verdict": "allow"}}}).encode() + b"\n")
    return s.makefile().readline()

if json.loads(ask("status")).get("error"):
    print("ESCAPED: the broker does not answer status, so this check proves nothing"); sys.exit(1)
for method in ("approvals.decide", "approvals.list", "session.info"):
    s = socket.socket(socket.AF_UNIX)
    s.connect(os.environ["GIRDLE_BROKER"])
    try:
        s.sendall(json.dumps({"method": method, "params": {"id": "x", "decision": {"verdict": "allow"}}}).encode() + b"\n")
        line = s.makefile().readline()
    except OSError:
        continue
    if line and not json.loads(line).get("error"):
        print("ESCAPED: the broker answered", method, line); sys.exit(1)
PY
