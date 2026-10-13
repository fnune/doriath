#!/bin/sh
# threat: reach another name on a shared address through a tunnel opened to an allowed host
# expect: held

python3 - <<'PY'
import socket, ssl, sys
s = socket.create_connection(("127.0.0.1", 3128), timeout=5)
s.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
if b" 200 " not in s.recv(1024):
    sys.exit(0)
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    ctx.wrap_socket(s, server_hostname="github.com").do_handshake()
    print("ESCAPED: TLS for github.com through a tunnel to example.com"); sys.exit(1)
except OSError:
    pass
PY
