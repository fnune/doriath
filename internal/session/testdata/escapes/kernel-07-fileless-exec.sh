#!/bin/sh
# threat: run a program from memory, which Landlock cannot see
# expect: gap

python3 - <<'PY'
import os, sys
try:
    fd = os.memfd_create("payload")
except OSError:
    sys.exit(0)
print("ESCAPED: memfd_create works"); sys.exit(1)
PY
