#!/bin/sh
# threat: create namespaces, the first step of most container escapes
# expect: held

unshare -U true 2>/dev/null && { echo "ESCAPED: unshare -U"; exit 1; }
unshare -n true 2>/dev/null && { echo "ESCAPED: unshare -n"; exit 1; }
python3 - <<'PY'
import os, sys
for flag in ("CLONE_NEWUSER", "CLONE_NEWNS", "CLONE_NEWNET", "CLONE_NEWPID"):
    try:
        os.unshare(getattr(os, flag))
    except (OSError, AttributeError):
        continue
    print("ESCAPED: unshare", flag); sys.exit(1)
PY
