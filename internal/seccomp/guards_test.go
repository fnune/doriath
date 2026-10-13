package seccomp

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

type syscallCall struct {
	nr   uint32
	arch uint32
	arg0 uint64
	arg1 uint64
}

func (c syscallCall) load(t *testing.T, off uint32) uint32 {
	t.Helper()
	switch off {
	case offsetNr:
		return c.nr
	case offsetArch:
		return c.arch
	case offsetArg0Low:
		return uint32(c.arg0)
	case offsetArg1Low:
		return uint32(c.arg1)
	}
	t.Fatalf("load from unexpected offset %d", off)
	return 0
}

func evaluate(t *testing.T, filter []byte, c syscallCall) uint32 {
	t.Helper()
	n := len(filter) / 8
	var acc uint32
	for pc := 0; pc < n; pc++ {
		raw := filter[pc*8:]
		code := binary.LittleEndian.Uint16(raw)
		jt, jf := int(raw[2]), int(raw[3])
		k := binary.LittleEndian.Uint32(raw[4:])
		switch code {
		case opLoad:
			acc = c.load(t, k)
		case opJa:
			pc += int(k)
		case opJeq:
			if acc == k {
				pc += jt
			} else {
				pc += jf
			}
		case opJset:
			if acc&k != 0 {
				pc += jt
			} else {
				pc += jf
			}
		case opRet:
			return k
		default:
			t.Fatalf("pc %d: unexpected opcode %#x", pc, code)
		}
		if pc+1 >= n {
			t.Fatalf("pc %d: jump past the end", pc)
		}
	}
	t.Fatal("filter fell off the end without returning")
	return 0
}

func decide(t *testing.T, arch Arch, p Policy, c syscallCall) uint32 {
	t.Helper()
	filter, err := Build(arch, p)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := arch.audit()
	if err != nil {
		t.Fatal(err)
	}
	c.arch = audit
	return evaluate(t, filter, c)
}

func numbersFor(t *testing.T, arch Arch) map[string]uint32 {
	t.Helper()
	nums, err := syscallNumbers(arch)
	if err != nil {
		t.Fatal(err)
	}
	return nums
}

func TestEveryDeniedSyscallIsDenied(t *testing.T) {
	eperm := []string{
		"kexec_load", "kexec_file_load", "init_module", "finit_module", "delete_module",
		"bpf", "perf_event_open", "userfaultfd", "keyctl", "add_key", "request_key",
		"acct", "swapon", "swapoff", "reboot", "open_by_handle_at", "name_to_handle_at",
		"quotactl", "quotactl_fd", "lookup_dcookie", "pidfd_getfd", "process_vm_readv",
		"process_vm_writev", "kcmp", "process_madvise", "ptrace",
		"mount", "umount2", "pivot_root", "chroot", "move_mount", "open_tree", "fsopen",
		"fsconfig", "fsmount", "fspick", "mount_setattr", "setns", "unshare",
	}
	enosys := []string{"io_uring_setup", "io_uring_enter", "io_uring_register", "clone3"}
	for _, arch := range []Arch{AMD64, ARM64} {
		nums := numbersFor(t, arch)
		names := eperm
		if arch == AMD64 {
			names = append([]string{"iopl", "ioperm"}, eperm...)
		}
		for _, name := range names {
			if got := decide(t, arch, Policy{}, syscallCall{nr: nums[name]}); got != retEPERM {
				t.Errorf("%s %s: got %#x, want EPERM", arch, name, got)
			}
		}
		for _, name := range enosys {
			if got := decide(t, arch, Policy{}, syscallCall{nr: nums[name]}); got != retENOSYS {
				t.Errorf("%s %s: got %#x, want ENOSYS", arch, name, got)
			}
		}
	}
}

func TestTerminalInjectionIoctlsAreDenied(t *testing.T) {
	for _, arch := range []Arch{AMD64, ARM64} {
		ioctl := numbersFor(t, arch)["ioctl"]
		for _, req := range []uint64{unix.TIOCSTI, unix.TIOCLINUX} {
			if got := decide(t, arch, Policy{}, syscallCall{nr: ioctl, arg1: req}); got != retEPERM {
				t.Errorf("%s ioctl %#x: got %#x, want EPERM", arch, req, got)
			}
		}
		for _, req := range []uint64{unix.TCGETS, unix.TIOCGWINSZ, unix.TIOCINQ} {
			if got := decide(t, arch, Policy{}, syscallCall{nr: ioctl, arg1: req}); got != retAllow {
				t.Errorf("%s ioctl %#x: got %#x, want allow", arch, req, got)
			}
		}
	}
}

func TestExoticSocketFamiliesAreDenied(t *testing.T) {
	denied := []uint64{
		unix.AF_PACKET, unix.AF_ALG, unix.AF_VSOCK, unix.AF_KEY, unix.AF_XDP,
		unix.AF_BLUETOOTH, unix.AF_CAN, unix.AF_TIPC, unix.AF_RDS, unix.AF_LLC,
		unix.AF_NFC, unix.AF_SMC, unix.AF_KCM, unix.AF_QIPCRTR, unix.AF_MCTP,
	}
	for _, arch := range []Arch{AMD64, ARM64} {
		socket := numbersFor(t, arch)["socket"]
		for _, family := range denied {
			if got := decide(t, arch, Policy{}, syscallCall{nr: socket, arg0: family}); got != retEPERM {
				t.Errorf("%s socket family %d: got %#x, want EPERM", arch, family, got)
			}
		}
		for _, family := range []uint64{unix.AF_UNIX, unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK} {
			if got := decide(t, arch, Policy{}, syscallCall{nr: socket, arg0: family}); got != retAllow {
				t.Errorf("%s socket family %d: got %#x, want allow", arch, family, got)
			}
		}
	}
}

func TestEveryNamespaceCloneFlagIsDenied(t *testing.T) {
	flags := []uint64{
		unix.CLONE_NEWUSER, unix.CLONE_NEWNS, unix.CLONE_NEWNET, unix.CLONE_NEWPID,
		unix.CLONE_NEWIPC, unix.CLONE_NEWUTS, unix.CLONE_NEWCGROUP, unix.CLONE_NEWTIME,
	}
	for _, arch := range []Arch{AMD64, ARM64} {
		clone := numbersFor(t, arch)["clone"]
		for _, flag := range flags {
			c := syscallCall{nr: clone, arg0: flag | uint64(unix.SIGCHLD)}
			if got := decide(t, arch, Policy{}, c); got != retEPERM {
				t.Errorf("%s clone %#x: got %#x, want EPERM", arch, flag, got)
			}
			if got := decide(t, arch, Policy{AllowNamespaces: true}, c); got != retAllow {
				t.Errorf("%s clone %#x with namespaces allowed: got %#x, want allow", arch, flag, got)
			}
		}
	}
}

func TestArgumentRulesOnlyApplyToTheirSyscall(t *testing.T) {
	read := map[Arch]uint32{AMD64: 0, ARM64: 63}
	for _, arch := range []Arch{AMD64, ARM64} {
		c := syscallCall{nr: read[arch], arg0: unix.AF_PACKET, arg1: unix.TIOCSTI}
		if got := decide(t, arch, Policy{}, c); got != retAllow {
			t.Errorf("%s read with matching arguments: got %#x, want allow", arch, got)
		}
	}
}
