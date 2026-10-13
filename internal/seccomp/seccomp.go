// Package seccomp builds the classic BPF filter that bubblewrap loads with
// --seccomp. The filter denies syscalls that reach past the jail: new
// namespaces and mounts, kernel modules and kexec, keyrings, BPF, and access
// to other processes' memory. Everything else is allowed.
package seccomp

import (
	"encoding/binary"
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

type Arch string

const (
	AMD64 Arch = "amd64"
	ARM64 Arch = "arm64"
)

func HostArch() (Arch, error) {
	switch a := Arch(runtime.GOARCH); a {
	case AMD64, ARM64:
		return a, nil
	default:
		return "", fmt.Errorf("seccomp filter not available for architecture %q", runtime.GOARCH)
	}
}

func (a Arch) audit() (uint32, error) {
	switch a {
	case AMD64:
		return unix.AUDIT_ARCH_X86_64, nil
	case ARM64:
		return unix.AUDIT_ARCH_AARCH64, nil
	default:
		return 0, fmt.Errorf("unknown architecture %q", a)
	}
}

type Policy struct {
	// AllowNamespaces lets the jailed process create namespaces and mounts,
	// so a nested sandbox such as bubblewrap works.
	AllowNamespaces bool
	AllowPtrace     bool
}

// Offsets into struct seccomp_data.
const (
	offsetNr   = 0
	offsetArch = 4
	// The low half of args[0] on a little-endian machine. amd64 and arm64 are
	// both little-endian.
	offsetArg0Low = 16
)

// x32 syscalls on x86_64 carry this bit in their number and share the
// AUDIT_ARCH_X86_64 arch, so without this check they would slip past every
// rule keyed on a syscall number.
const x32SyscallBit = 0x40000000

const namespaceCloneFlags = unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWNET |
	unix.CLONE_NEWPID | unix.CLONE_NEWIPC | unix.CLONE_NEWUTS | unix.CLONE_NEWCGROUP |
	unix.CLONE_NEWTIME

const (
	retAllow = unix.SECCOMP_RET_ALLOW
	retKill  = unix.SECCOMP_RET_KILL_PROCESS
	retEPERM = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)&unix.SECCOMP_RET_DATA
	// ENOSYS makes callers believe the kernel lacks the syscall, so they take
	// their fallback path instead of failing.
	retENOSYS = unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)&unix.SECCOMP_RET_DATA
)

type rule struct {
	syscall string
	ret     uint32
}

func rules(arch Arch, p Policy) []rule {
	deny := func(ret uint32, names ...string) []rule {
		rs := make([]rule, 0, len(names))
		for _, n := range names {
			rs = append(rs, rule{syscall: n, ret: ret})
		}
		return rs
	}
	rs := deny(retEPERM,
		"kexec_load", "kexec_file_load", "init_module", "finit_module", "delete_module",
		"bpf", "perf_event_open", "userfaultfd",
		"keyctl", "add_key", "request_key",
		"acct", "swapon", "swapoff", "reboot",
		"open_by_handle_at", "name_to_handle_at",
		"quotactl", "quotactl_fd", "lookup_dcookie",
		"pidfd_getfd", "process_vm_readv", "process_vm_writev",
	)
	if arch == AMD64 {
		rs = append(rs, deny(retEPERM, "iopl", "ioperm")...)
	}
	if !p.AllowPtrace {
		rs = append(rs, deny(retEPERM, "ptrace")...)
	}
	rs = append(rs, deny(retENOSYS, "io_uring_setup", "io_uring_enter", "io_uring_register")...)
	if !p.AllowNamespaces {
		rs = append(rs, deny(retEPERM,
			"mount", "umount2", "pivot_root", "chroot",
			"move_mount", "open_tree", "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr",
			"setns", "unshare",
		)...)
		// clone3 passes its flags in a struct that classic BPF cannot read.
		// glibc falls back to clone on ENOSYS, and clone's flags are checked
		// below.
		rs = append(rs, deny(retENOSYS, "clone3")...)
	}
	return rs
}

func stmt(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }

func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

const (
	opLoad = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
	opJeq  = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
	opJset = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
	opRet  = unix.BPF_RET | unix.BPF_K
)

func program(arch Arch, p Policy) ([]unix.SockFilter, error) {
	audit, err := arch.audit()
	if err != nil {
		return nil, err
	}
	numbers, err := syscallNumbers(arch)
	if err != nil {
		return nil, err
	}
	prog := []unix.SockFilter{
		stmt(opLoad, offsetArch),
		jump(opJeq, audit, 1, 0),
		stmt(opRet, retKill),
		stmt(opLoad, offsetNr),
	}
	if arch == AMD64 {
		prog = append(prog,
			jump(opJset, x32SyscallBit, 0, 1),
			stmt(opRet, retKill),
		)
	}
	for _, r := range rules(arch, p) {
		nr, ok := numbers[r.syscall]
		if !ok {
			return nil, fmt.Errorf("no number for syscall %s on %s", r.syscall, arch)
		}
		prog = append(prog,
			jump(opJeq, nr, 0, 1),
			stmt(opRet, r.ret),
		)
	}
	if !p.AllowNamespaces {
		// Thread creation goes through clone too, so only the namespace flags
		// are refused. They all sit in the low 32 bits.
		prog = append(prog,
			jump(opJeq, numbers["clone"], 0, 3),
			stmt(opLoad, offsetArg0Low),
			jump(opJset, namespaceCloneFlags, 0, 1),
			stmt(opRet, retEPERM),
		)
	}
	return append(prog, stmt(opRet, retAllow)), nil
}

// Build returns the filter as bubblewrap reads it from --seccomp: an array of
// struct sock_filter in the target's byte order.
func Build(arch Arch, p Policy) ([]byte, error) {
	prog, err := program(arch, p)
	if err != nil {
		return nil, fmt.Errorf("build seccomp filter for %s: %w", arch, err)
	}
	return encode(prog), nil
}

func encode(prog []unix.SockFilter) []byte {
	out := make([]byte, 0, 8*len(prog))
	for _, ins := range prog {
		out = binary.LittleEndian.AppendUint16(out, ins.Code)
		out = append(out, ins.Jt, ins.Jf)
		out = binary.LittleEndian.AppendUint32(out, ins.K)
	}
	return out
}
