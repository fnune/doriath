package seccomp

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestTableMatchesUnix(t *testing.T) {
	want := map[string]uint32{
		"clone":             unix.SYS_CLONE,
		"ptrace":            unix.SYS_PTRACE,
		"pivot_root":        unix.SYS_PIVOT_ROOT,
		"chroot":            unix.SYS_CHROOT,
		"acct":              unix.SYS_ACCT,
		"mount":             unix.SYS_MOUNT,
		"umount2":           unix.SYS_UMOUNT2,
		"swapon":            unix.SYS_SWAPON,
		"swapoff":           unix.SYS_SWAPOFF,
		"reboot":            unix.SYS_REBOOT,
		"init_module":       unix.SYS_INIT_MODULE,
		"delete_module":     unix.SYS_DELETE_MODULE,
		"quotactl":          unix.SYS_QUOTACTL,
		"lookup_dcookie":    unix.SYS_LOOKUP_DCOOKIE,
		"kexec_load":        unix.SYS_KEXEC_LOAD,
		"add_key":           unix.SYS_ADD_KEY,
		"request_key":       unix.SYS_REQUEST_KEY,
		"keyctl":            unix.SYS_KEYCTL,
		"unshare":           unix.SYS_UNSHARE,
		"perf_event_open":   unix.SYS_PERF_EVENT_OPEN,
		"name_to_handle_at": unix.SYS_NAME_TO_HANDLE_AT,
		"open_by_handle_at": unix.SYS_OPEN_BY_HANDLE_AT,
		"setns":             unix.SYS_SETNS,
		"process_vm_readv":  unix.SYS_PROCESS_VM_READV,
		"process_vm_writev": unix.SYS_PROCESS_VM_WRITEV,
		"finit_module":      unix.SYS_FINIT_MODULE,
		"kexec_file_load":   unix.SYS_KEXEC_FILE_LOAD,
		"bpf":               unix.SYS_BPF,
		"userfaultfd":       unix.SYS_USERFAULTFD,
		"io_uring_setup":    unix.SYS_IO_URING_SETUP,
		"io_uring_enter":    unix.SYS_IO_URING_ENTER,
		"io_uring_register": unix.SYS_IO_URING_REGISTER,
		"open_tree":         unix.SYS_OPEN_TREE,
		"move_mount":        unix.SYS_MOVE_MOUNT,
		"fsopen":            unix.SYS_FSOPEN,
		"fsconfig":          unix.SYS_FSCONFIG,
		"fsmount":           unix.SYS_FSMOUNT,
		"fspick":            unix.SYS_FSPICK,
		"clone3":            unix.SYS_CLONE3,
		"pidfd_getfd":       unix.SYS_PIDFD_GETFD,
		"mount_setattr":     unix.SYS_MOUNT_SETATTR,
		"quotactl_fd":       unix.SYS_QUOTACTL_FD,
		"iopl":              unix.SYS_IOPL,
		"ioperm":            unix.SYS_IOPERM,
	}
	got, err := syscallNumbers(AMD64)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Errorf("table has %d syscalls, want %d", len(got), len(want))
	}
	for name, nr := range want {
		if got[name] != nr {
			t.Errorf("%s = %d, unix.SYS_ has %d", name, got[name], nr)
		}
	}
}
