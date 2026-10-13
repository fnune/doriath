package seccomp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

func TestEncodeLayout(t *testing.T) {
	got := encode([]unix.SockFilter{{Code: 0x0015, Jt: 1, Jf: 2, K: 0xc000003e}})
	want := []byte{0x15, 0x00, 0x01, 0x02, 0x3e, 0x00, 0x00, 0xc0}
	if !bytes.Equal(got, want) {
		t.Fatalf("encode = % x, want % x", got, want)
	}
}

type seccompData struct {
	nr   uint32
	arch uint32
	arg0 uint64
}

func (d seccompData) word(off uint32) (uint32, error) {
	switch off {
	case offsetNr:
		return d.nr, nil
	case offsetArch:
		return d.arch, nil
	case offsetArg0Low:
		return uint32(d.arg0), nil
	default:
		return 0, fmt.Errorf("load from unexpected offset %d", off)
	}
}

func run(t *testing.T, filter []byte, d seccompData) uint32 {
	t.Helper()
	if len(filter)%8 != 0 {
		t.Fatalf("filter length %d is not a multiple of 8", len(filter))
	}
	n := len(filter) / 8
	var acc uint32
	for pc := 0; pc < n; pc++ {
		raw := filter[pc*8:]
		code := binary.LittleEndian.Uint16(raw)
		jt, jf := int(raw[2]), int(raw[3])
		k := binary.LittleEndian.Uint32(raw[4:])
		switch code {
		case opLoad:
			w, err := d.word(k)
			if err != nil {
				t.Fatalf("pc %d: %v", pc, err)
			}
			acc = w
		case opJeq, opJset:
			taken := acc == k
			if code == opJset {
				taken = acc&k != 0
			}
			if taken {
				pc += jt
			} else {
				pc += jf
			}
			if pc+1 >= n {
				t.Fatalf("pc %d: jump past the end", pc)
			}
		case opRet:
			return k
		default:
			t.Fatalf("pc %d: unexpected opcode %#x", pc, code)
		}
	}
	t.Fatal("filter fell off the end without returning")
	return 0
}

type decision struct {
	name   string
	policy Policy
	data   seccompData
	want   uint32
}

func TestFilterDecisions(t *testing.T) {
	const cloneThread = unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND |
		unix.CLONE_THREAD | unix.CLONE_SYSVSEM | unix.CLONE_SETTLS |
		unix.CLONE_PARENT_SETTID | unix.CLONE_CHILD_CLEARTID
	for _, arch := range []Arch{AMD64, ARM64} {
		audit, err := arch.audit()
		if err != nil {
			t.Fatal(err)
		}
		nums, err := syscallNumbers(arch)
		if err != nil {
			t.Fatal(err)
		}
		cases := []decision{
			{"wrong arch", Policy{}, seccompData{nr: 0, arch: unix.AUDIT_ARCH_I386}, retKill},
			{"ordinary syscall", Policy{}, seccompData{nr: 63, arch: audit}, retAllow},
			{"mount", Policy{}, seccompData{nr: nums["mount"], arch: audit}, retEPERM},
			{"unshare", Policy{}, seccompData{nr: nums["unshare"], arch: audit}, retEPERM},
			{"bpf", Policy{}, seccompData{nr: nums["bpf"], arch: audit}, retEPERM},
			{"ptrace", Policy{}, seccompData{nr: nums["ptrace"], arch: audit}, retEPERM},
			{"ptrace allowed", Policy{AllowPtrace: true}, seccompData{nr: nums["ptrace"], arch: audit}, retAllow},
			{"io_uring", Policy{}, seccompData{nr: nums["io_uring_setup"], arch: audit}, retENOSYS},
			{"clone3", Policy{}, seccompData{nr: nums["clone3"], arch: audit}, retENOSYS},
			{"clone thread", Policy{}, seccompData{nr: nums["clone"], arch: audit, arg0: cloneThread}, retAllow},
			{"clone fork", Policy{}, seccompData{nr: nums["clone"], arch: audit, arg0: uint64(unix.SIGCHLD)}, retAllow},
			{"clone newuser", Policy{}, seccompData{nr: nums["clone"], arch: audit, arg0: unix.CLONE_NEWUSER | uint64(unix.SIGCHLD)}, retEPERM},
			{"clone newnet", Policy{}, seccompData{nr: nums["clone"], arch: audit, arg0: unix.CLONE_NEWNET}, retEPERM},
			{"namespaces: unshare", Policy{AllowNamespaces: true}, seccompData{nr: nums["unshare"], arch: audit}, retAllow},
			{"namespaces: mount", Policy{AllowNamespaces: true}, seccompData{nr: nums["mount"], arch: audit}, retAllow},
			{"namespaces: clone3", Policy{AllowNamespaces: true}, seccompData{nr: nums["clone3"], arch: audit}, retAllow},
			{"namespaces: clone newuser", Policy{AllowNamespaces: true}, seccompData{nr: nums["clone"], arch: audit, arg0: unix.CLONE_NEWUSER}, retAllow},
			{"namespaces: kexec still denied", Policy{AllowNamespaces: true}, seccompData{nr: nums["kexec_load"], arch: audit}, retEPERM},
		}
		if arch == AMD64 {
			cases = append(cases,
				decision{"x32", Policy{}, seccompData{nr: x32SyscallBit | nums["mount"], arch: audit}, retKill},
				decision{"iopl", Policy{}, seccompData{nr: nums["iopl"], arch: audit}, retEPERM},
			)
		}
		for _, c := range cases {
			t.Run(string(arch)+"/"+c.name, func(t *testing.T) {
				filter, err := Build(arch, c.policy)
				if err != nil {
					t.Fatal(err)
				}
				if got := run(t, filter, c.data); got != c.want {
					t.Fatalf("got %#x, want %#x", got, c.want)
				}
			})
		}
	}
}

func TestEveryRuleHasANumber(t *testing.T) {
	for _, arch := range []Arch{AMD64, ARM64} {
		for _, p := range []Policy{{}, {AllowNamespaces: true, AllowPtrace: true}} {
			if _, err := Build(arch, p); err != nil {
				t.Errorf("%s %+v: %v", arch, p, err)
			}
		}
	}
}

func TestUnknownArch(t *testing.T) {
	if _, err := Build("riscv64", Policy{}); err == nil {
		t.Fatal("want an error for an unknown architecture")
	}
}

func TestFilterStartsWithArchCheck(t *testing.T) {
	prog, err := program(ARM64, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	want := []unix.SockFilter{
		{Code: opLoad, K: offsetArch},
		{Code: opJeq, Jt: 1, K: unix.AUDIT_ARCH_AARCH64},
		{Code: opRet, K: retKill},
		{Code: opLoad, K: offsetNr},
	}
	for i, w := range want {
		if prog[i] != w {
			t.Fatalf("instruction %d = %+v, want %+v", i, prog[i], w)
		}
	}
	if last := prog[len(prog)-1]; last != (unix.SockFilter{Code: opRet, K: retAllow}) {
		t.Fatalf("last instruction = %+v, want allow", last)
	}
}
