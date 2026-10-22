#!/bin/sh
# threat: type commands into the terminal that started doriath
# expect: held

python3 - <<'PY'
import errno, fcntl, sys, termios
for request in (termios.TIOCSTI,):
    try:
        fcntl.ioctl(0, request, b"x")
    except OSError as e:
        if e.errno == errno.EPERM:
            continue
    print("ESCAPED: TIOCSTI is not refused"); sys.exit(1)
PY
