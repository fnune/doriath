package seccomp

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const helperEnv = "GIRDLE_SECCOMP_HELPER"

// TestHelperProcess is the program the jail runs when a test needs a Go
// process with many OS threads. It does nothing in a normal test run.
func TestHelperProcess(t *testing.T) {
	if os.Getenv(helperEnv) != "threads" {
		return
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
		})
	}
	wg.Wait()
	_, _ = os.Stdout.WriteString("threads ok\n")
	os.Exit(0)
}

type jail struct {
	bwrap  string
	filter string
}

func newJail(t *testing.T, p Policy) jail {
	t.Helper()
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bwrap not installed")
	}
	arch, err := HostArch()
	if err != nil {
		t.Skip(err)
	}
	filter, err := Build(arch, p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "filter.bpf")
	if err := os.WriteFile(path, filter, 0o600); err != nil {
		t.Fatal(err)
	}
	return jail{bwrap: bwrap, filter: path}
}

func (j jail) run(t *testing.T, env []string, argv ...string) (string, error) {
	t.Helper()
	f, err := os.Open(j.filter)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	args := []string{
		"--unshare-user", "--unshare-pid",
		"--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
		"--seccomp", "3", "--",
	}
	cmd := exec.Command(j.bwrap, append(args, argv...)...)
	cmd.ExtraFiles = []*os.File{f}
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func lookPath(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not installed", name)
	}
	return p
}

func TestJailAllowsOrdinaryPrograms(t *testing.T) {
	j := newJail(t, Policy{})
	cases := []struct {
		name string
		env  []string
		argv []string
		want string
	}{
		{"shell", nil, []string{"sh", "-c", "echo ok"}, "ok"},
		{"ls", nil, []string{lookPath(t, "ls"), "/"}, "proc"},
		{"go threads", []string{helperEnv + "=threads"}, []string{os.Args[0], "-test.run=^TestHelperProcess$"}, "threads ok"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := j.run(t, c.env, c.argv...)
			if err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			if !strings.Contains(out, c.want) {
				t.Fatalf("output %q does not contain %q", out, c.want)
			}
		})
	}
}

// glibc 2.34 and later start threads with clone3, so this checks that the
// ENOSYS fallback to clone works.
func TestJailAllowsGlibcThreads(t *testing.T) {
	j := newJail(t, Policy{})
	python := lookPath(t, "python3")
	script := "import threading; t = threading.Thread(target=print, args=('thread ok',)); t.start(); t.join()"
	out, err := j.run(t, nil, python, "-c", script)
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !strings.Contains(out, "thread ok") {
		t.Fatalf("output %q", out)
	}
}

func TestJailDeniesNamespaces(t *testing.T) {
	j := newJail(t, Policy{})
	unshare := lookPath(t, "unshare")
	out, err := j.run(t, nil, unshare, "-U", "true")
	if err == nil {
		t.Fatalf("unshare -U succeeded: %s", out)
	}
	if !strings.Contains(out, "Operation not permitted") {
		t.Fatalf("unshare failed for another reason: %s", out)
	}
	out, err = j.run(t, nil, j.bwrap, "--unshare-all", "--ro-bind", "/", "/", "true")
	if err == nil {
		t.Fatalf("nested bwrap succeeded: %s", out)
	}
}

func TestJailAllowsNestedSandbox(t *testing.T) {
	j := newJail(t, Policy{AllowNamespaces: true})
	out, err := j.run(t, nil, j.bwrap, "--unshare-all", "--ro-bind", "/", "/", "true")
	if err != nil {
		t.Fatalf("nested bwrap: %v: %s", err, out)
	}
}
