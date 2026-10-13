#!/bin/sh
# threat: use ptrace, BPF, io_uring, kernel modules or keyrings
# expect: held

python3 - <<'PY'
import ctypes, errno, os, platform, sys
libc = ctypes.CDLL(None, use_errno=True)
arm = platform.machine() in ("aarch64", "arm64")
def refused(nr, *args):
    ctypes.set_errno(0)
    r = libc.syscall(nr, *args)
    e = ctypes.get_errno()
    return r == -1 and e in (errno.EPERM, errno.ENOSYS, errno.EACCES)

calls = {
    "ptrace": (117, 0) if arm else (101, 0),
    "bpf": (280, 0) if arm else (321, 0),
    "io_uring_setup": (425, 1, 0),
    "init_module": (105, 0, 0, 0) if arm else (175, 0, 0, 0),
    "finit_module": (273, -1, 0, 0) if arm else (313, -1, 0, 0),
    "add_key": (217, 0, 0, 0, 0, 0) if arm else (248, 0, 0, 0, 0, 0),
    "keyctl": (219, 0) if arm else (250, 0),
    "kexec_load": (104, 0, 0, 0, 0) if arm else (246, 0, 0, 0, 0),
}
for name, (nr, *args) in calls.items():
    if not refused(nr, *args):
        print("ESCAPED:", name, "is not refused"); sys.exit(1)
PY
