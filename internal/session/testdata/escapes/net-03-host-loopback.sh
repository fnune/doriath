#!/bin/sh
# threat: reach services listening on the host's localhost
# expect: held
# setup: host-listener

python3 - <<'PY'
import socket, sys
s = socket.socket()
s.settimeout(2)
try:
    s.connect(("127.0.0.1", {{HOST_PORT}}))
    print("ESCAPED: reached the host's port {{HOST_PORT}}:", s.recv(64)); sys.exit(1)
except OSError:
    pass
PY
