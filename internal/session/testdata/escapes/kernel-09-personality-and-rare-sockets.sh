#!/bin/sh
# threat: reach rarely used kernel code through odd socket families, or weaken the address space through personality
# expect: held

python3 - <<'PY'
import ctypes, errno, platform, socket, sys
libc = ctypes.CDLL(None, use_errno=True)
arm = platform.machine() in ("aarch64", "arm64")
ctypes.set_errno(0)
r = libc.syscall(92 if arm else 135, 0x0400000)
if r != -1 or ctypes.get_errno() != errno.EPERM:
    print("ESCAPED: personality(READ_IMPLIES_EXEC) is not refused"); sys.exit(1)
ctypes.set_errno(0)
r = libc.syscall(116 if arm else 103, 3, 0, 0)
if r != -1 or ctypes.get_errno() not in (errno.EPERM, errno.ENOSYS):
    print("ESCAPED: syslog read the kernel log"); sys.exit(1)
for family in (24, 33, 9, 3, 5, 34):
    try:
        socket.socket(family, socket.SOCK_DGRAM, 0)
    except OSError as e:
        if e.errno != errno.EPERM:
            print("ESCAPED: family", family, "is not refused by the filter:", e); sys.exit(1)
        continue
    print("ESCAPED: a socket of family", family, "was created"); sys.exit(1)
PY
