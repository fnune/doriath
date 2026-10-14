#!/bin/sh
# threat: reach another name on a shared address through a tunnel opened to an allowed host, by greeting another name, waiting out the check, or sending no name
# expect: held

python3 - <<'PY'
import socket, ssl, sys, time
def tunnel():
    s = socket.create_connection(("127.0.0.1", 3128), timeout=10)
    s.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
    if b" 200 " not in s.recv(1024):
        return None
    return s
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
for label, delay, name in [("another name", 0, "github.com"), ("another name after a wait", 4, "github.com"), ("no name", 0, None)]:
    s = tunnel()
    if s is None:
        continue
    time.sleep(delay)
    try:
        ctx.wrap_socket(s, server_hostname=name).do_handshake()
        print("ESCAPED: TLS with %s through a tunnel to example.com" % label); sys.exit(1)
    except OSError:
        pass
PY
