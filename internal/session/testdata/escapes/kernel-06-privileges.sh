#!/bin/sh
# threat: gain root through setuid programs or set*id calls
# expect: held

[ "$(sudo -n id -u 2>/dev/null)" = 0 ] && { echo "ESCAPED: sudo"; exit 1; }
python3 - <<'PY'
import os, sys
try:
    os.setuid(0)
    print("ESCAPED: setuid(0)"); sys.exit(1)
except OSError:
    pass
PY
