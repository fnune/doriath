#!/bin/sh
# threat: use packet sockets or other rarely used kernel network code
# expect: held

python3 - <<'PY'
import socket, sys
for name in ("AF_PACKET", "AF_ALG", "AF_VSOCK", "AF_KEY", "AF_XDP", "AF_BLUETOOTH", "AF_CAN", "AF_TIPC", "AF_RDS"):
    family = getattr(socket, name, None)
    if family is None:
        continue
    for kind in (socket.SOCK_RAW, socket.SOCK_DGRAM, socket.SOCK_SEQPACKET, socket.SOCK_STREAM):
        try:
            socket.socket(family, kind).close()
        except PermissionError:
            break
        except OSError:
            continue
        print("ESCAPED: opened", name); sys.exit(1)
PY
