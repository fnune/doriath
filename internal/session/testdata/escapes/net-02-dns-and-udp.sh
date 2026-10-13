#!/bin/sh
# threat: send data out through DNS or other UDP
# expect: held

python3 - <<'PY'
import socket, sys
try:
    socket.getaddrinfo("example.com", 443)
    print("ESCAPED: resolved a name in the jail"); sys.exit(1)
except OSError:
    pass
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
try:
    s.sendto(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01", ("8.8.8.8", 53))
    s.recvfrom(512)
    print("ESCAPED: got a DNS answer over UDP"); sys.exit(1)
except OSError:
    pass
PY
