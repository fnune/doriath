package seccomp

import (
	"maps"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

var (
	alwaysDenied = []string{
		"kexec_load", "kexec_file_load", "init_module", "finit_module", "delete_module",
		"bpf", "perf_event_open", "userfaultfd", "keyctl", "add_key", "request_key",
		"acct", "swapon", "swapoff", "reboot", "open_by_handle_at", "name_to_handle_at",
		"quotactl", "quotactl_fd", "lookup_dcookie", "pidfd_getfd", "process_vm_readv",
		"process_vm_writev", "kcmp", "process_madvise", "syslog",
	}
	namespaceDenied = []string{
		"mount", "umount2", "pivot_root", "chroot", "move_mount", "open_tree", "fsopen",
		"fsconfig", "fsmount", "fspick", "mount_setattr", "setns", "unshare",
	}
	ioUring = []string{"io_uring_setup", "io_uring_enter", "io_uring_register"}
)

func expected(arch Arch, p Policy, name string, nr uint32, arg0, arg1 uint64) uint32 {
	switch {
	case arch == AMD64 && nr&x32SyscallBit != 0:
		return retKill
	case slices.Contains(alwaysDenied, name),
		arch == AMD64 && (name == "iopl" || name == "ioperm"),
		!p.AllowPtrace && name == "ptrace",
		!p.AllowNamespaces && slices.Contains(namespaceDenied, name):
		return retEPERM
	case slices.Contains(ioUring, name), !p.AllowNamespaces && name == "clone3":
		return retENOSYS
	case name == "ioctl" && (uint32(arg1) == unix.TIOCSTI || uint32(arg1) == unix.TIOCLINUX),
		name == "socket" && slices.Contains(deniedFamilies, uint32(arg0)),
		name == "personality" && !slices.Contains(allowedPersonalities, uint32(arg0)),
		name == "clone" && !p.AllowNamespaces && uint32(arg0)&namespaceCloneFlags != 0:
		return retEPERM
	}
	return retAllow
}

func FuzzFilter(f *testing.F) {
	f.Add(false, false, false, true, uint16(0), uint32(0), uint64(0), uint64(0))
	f.Add(true, false, false, true, uint16(0xffff), uint32(x32SyscallBit|165), uint64(0), uint64(0))
	f.Add(true, false, false, false, uint16(0xffff), uint32(0), uint64(0), uint64(0))
	f.Add(false, true, true, true, uint16(0xffff), uint32(56), uint64(unix.CLONE_NEWUSER), uint64(0))
	f.Add(true, false, false, true, uint16(0xffff), uint32(56), uint64(1)<<32|unix.CLONE_NEWNET, uint64(0))
	f.Add(true, false, false, true, uint16(0xffff), uint32(41), uint64(unix.AF_PACKET), uint64(0))
	f.Add(true, false, false, true, uint16(0xffff), uint32(41), uint64(1)<<32|unix.AF_ALG, uint64(0))
	f.Add(true, false, false, true, uint16(0xffff), uint32(16), uint64(0), uint64(unix.TIOCSTI))
	f.Add(false, false, false, true, uint16(0xffff), uint32(29), uint64(0), uint64(unix.TIOCLINUX))
	type key struct {
		arch Arch
		p    Policy
	}
	filters := map[key][]byte{}
	for _, arch := range []Arch{AMD64, ARM64} {
		for _, p := range []Policy{{}, {AllowNamespaces: true}, {AllowPtrace: true}, {AllowNamespaces: true, AllowPtrace: true}} {
			filter, err := Build(arch, p)
			if err != nil {
				f.Fatal(err)
			}
			filters[key{arch, p}] = filter
		}
	}
	f.Fuzz(func(t *testing.T, amd64, namespaces, ptrace, nativeArch bool, pick uint16, nr uint32, arg0, arg1 uint64) {
		arch := ARM64
		if amd64 {
			arch = AMD64
		}
		p := Policy{AllowNamespaces: namespaces, AllowPtrace: ptrace}
		numbers, err := syscallNumbers(arch)
		if err != nil {
			t.Fatal(err)
		}
		names := slices.Sorted(maps.Keys(numbers))
		if int(pick) < len(names) {
			nr = numbers[names[pick]]
		}
		name := ""
		for n, number := range numbers {
			if number == nr {
				name = n
			}
		}
		audit, err := arch.audit()
		if err != nil {
			t.Fatal(err)
		}
		want := expected(arch, p, name, nr, arg0, arg1)
		if !nativeArch {
			audit ^= uint32(pick) | 1
			want = retKill
		}
		got := run(t, filters[key{arch, p}], seccompData{nr: nr, arch: audit, arg0: arg0, arg1: arg1})
		if got != want {
			t.Fatalf("%s %+v: syscall %d (%s) arg0 %#x arg1 %#x got %#x, want %#x", arch, p, nr, name, arg0, arg1, got, want)
		}
	})
}
