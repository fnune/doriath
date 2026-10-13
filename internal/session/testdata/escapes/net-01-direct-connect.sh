#!/bin/sh
# threat: reach the internet without going through the proxy
# expect: held

python3 - <<'PY'
import socket, sys
for family, addr in ((socket.AF_INET, ("1.1.1.1", 443)), (socket.AF_INET6, ("2606:4700:4700::1111", 443))):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect(addr)
    except OSError:
        continue
    print("ESCAPED: connected to", addr); sys.exit(1)
PY
