package confine

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestInstallSeccompRefusesAPartialProgram(t *testing.T) {
	for _, size := range []int{0, 7, 12} {
		err := InstallSeccomp(make([]byte, size))
		if err == nil || !strings.Contains(err.Error(), "not a whole number of instructions") {
			t.Errorf("%d bytes: err = %v", size, err)
		}
	}
}

func TestInstallSeccompLoadsTheProgramAsWritten(t *testing.T) {
	inChild(t, 0, func(t *testing.T) {
		if err := InstallSeccomp(refuseGetppid()); err != nil {
			t.Fatal(err)
		}
		if _, _, errno := unix.RawSyscall(unix.SYS_GETPPID, 0, 0, 0); errno != unix.EOPNOTSUPP {
			t.Fatalf("getppid: errno %v, want the filter's EOPNOTSUPP", errno)
		}
		if _, _, errno := unix.RawSyscall(unix.SYS_GETPID, 0, 0, 0); errno != 0 {
			t.Fatalf("getpid: errno %v, want it allowed", errno)
		}
	})
}

func TestDropCapabilitiesEmptiesEverySet(t *testing.T) {
	inChild(t, syscall.CLONE_NEWUSER, func(t *testing.T) {
		if capabilities(t)["CapEff"] == 0 {
			t.Fatal("root in a user namespace of its own holds no capabilities")
		}
		if err := DropCapabilities(); err != nil {
			t.Fatal(err)
		}
		for set, value := range capabilities(t) {
			if value != 0 {
				t.Errorf("%s = %x", set, value)
			}
		}
	})
}

func TestDropCapabilitiesLeavesAProcessWithoutCapabilitiesAlone(t *testing.T) {
	inChild(t, 0, func(t *testing.T) {
		if capabilities(t)["CapEff"] != 0 {
			t.Skip("the test runs with capabilities")
		}
		bounding := capabilities(t)["CapBnd"]
		if err := DropCapabilities(); err != nil {
			t.Fatal(err)
		}
		if got := capabilities(t)["CapBnd"]; got != bounding {
			t.Errorf("the bounding set changed from %x to %x", bounding, got)
		}
	})
}

// refuseGetppid fails getppid with EOPNOTSUPP and allows the rest. Its jump
// offsets differ, so swapped fields would fail the test.
func refuseGetppid() []byte {
	type insn struct {
		code   uint16
		jt, jf uint8
		k      uint32
	}
	prog := []insn{
		{code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, k: 0},
		{code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, jt: 0, jf: 1, k: unix.SYS_GETPPID},
		{code: unix.BPF_RET | unix.BPF_K, k: unix.SECCOMP_RET_ERRNO | uint32(unix.EOPNOTSUPP)},
		{code: unix.BPF_RET | unix.BPF_K, k: unix.SECCOMP_RET_ALLOW},
	}
	var out []byte
	for _, i := range prog {
		out = binary.LittleEndian.AppendUint16(out, i.code)
		out = append(out, i.jt, i.jf)
		out = binary.LittleEndian.AppendUint32(out, i.k)
	}
	return out
}

// capabilities reads the calling thread's capability sets, which is where
// both functions act.
func capabilities(t *testing.T) map[string]uint64 {
	t.Helper()
	data, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]uint64{}
	for _, line := range strings.Split(string(data), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || !strings.HasPrefix(name, "Cap") {
			continue
		}
		var n uint64
		for _, c := range strings.TrimSpace(value) {
			n = n<<4 | uint64(strings.IndexRune("0123456789abcdef", c))
		}
		out[name] = n
	}
	return out
}

const childEnv = "DORIATH_CONFINE_TEST_CHILD"

// inChild runs body on a locked thread of a copy of the test binary, since
// a seccomp filter or a dropped capability cannot be undone. With
// CLONE_NEWUSER the copy is root in a user namespace of its own.
func inChild(t *testing.T, cloneflags uintptr, body func(t *testing.T)) {
	t.Helper()
	if os.Getenv(childEnv) == t.Name() {
		runtime.LockOSThread()
		body(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"="+t.Name())
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: cloneflags}
	if cloneflags&syscall.CLONE_NEWUSER != 0 {
		cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
		cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
	}
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err != nil && !errors.As(err, &exit):
		t.Skipf("cannot start the child: %v", err)
	case err != nil:
		t.Fatalf("%v:\n%s", err, out)
	case strings.Contains(string(out), "--- SKIP: "+t.Name()):
		t.Skipf("%s", out)
	case !strings.Contains(string(out), "--- PASS: "+t.Name()):
		t.Fatalf("the child did not run the test:\n%s", out)
	}
}
