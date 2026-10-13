package landlock

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const helperEnv = "GIRDLE_LANDLOCK_HELPER"

func TestABI(t *testing.T) {
	abi, err := ABI()
	if errors.Is(err, ErrUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if abi < 1 {
		t.Fatalf("ABI = %d, want at least 1", abi)
	}
	if handledRights(abi)&unix.LANDLOCK_ACCESS_FS_READ_FILE != 0 {
		t.Fatal("reads must not be handled")
	}
}

func TestHandledRightsFollowABI(t *testing.T) {
	if handledRights(1)&(unix.LANDLOCK_ACCESS_FS_REFER|unix.LANDLOCK_ACCESS_FS_TRUNCATE) != 0 {
		t.Fatal("ABI 1 has neither REFER nor TRUNCATE")
	}
	if handledRights(2)&unix.LANDLOCK_ACCESS_FS_REFER == 0 {
		t.Fatal("ABI 2 handles REFER")
	}
	if handledRights(3)&unix.LANDLOCK_ACCESS_FS_TRUNCATE == 0 {
		t.Fatal("ABI 3 handles TRUNCATE")
	}
}

// TestHelperProcess runs the restricted side of a test in a fresh process,
// because the restriction cannot be undone. It does nothing in a normal
// test run.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv(helperEnv)
	if mode == "" {
		return
	}
	if err := helper(mode, os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func helper(mode, allowed, denied string) error {
	missing := filepath.Join(allowed, "does-not-exist")
	switch mode {
	case "restrict":
		runtime.LockOSThread()
		if err := RestrictWrites([]string{missing, allowed}); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(allowed, "new"), []byte("ok"), 0o600); err != nil {
			return fmt.Errorf("write to allowed dir: %w", err)
		}
		err := os.WriteFile(filepath.Join(denied, "new"), []byte("no"), 0o600)
		if !errors.Is(err, unix.EACCES) {
			return fmt.Errorf("write to denied dir: got %w, want EACCES", err)
		}
		if err := os.WriteFile(filepath.Join(denied, "existing"), []byte("no"), 0o600); !errors.Is(err, unix.EACCES) {
			return fmt.Errorf("overwrite in denied dir: got %w, want EACCES", err)
		}
		data, err := os.ReadFile(filepath.Join(denied, "existing"))
		if err != nil || string(data) != "before" {
			return fmt.Errorf("read denied dir: %q, %w", data, err)
		}
		return nil
	case "exec":
		sh, err := exec.LookPath("sh")
		if err != nil {
			return err
		}
		script := fmt.Sprintf("echo ok > %s/new && ! echo no > %s/new 2>/dev/null && cat %s/existing",
			allowed, denied, denied)
		runtime.LockOSThread()
		if err := RestrictWrites([]string{allowed}); err != nil {
			return err
		}
		return syscall.Exec(sh, []string{"sh", "-c", script}, os.Environ())
	default:
		return fmt.Errorf("unknown helper mode %q", mode)
	}
}

func runHelper(t *testing.T, mode string) string {
	t.Helper()
	if _, err := ABI(); errors.Is(err, ErrUnsupported) {
		t.Skip(err)
	}
	allowed, denied := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(denied, "existing"), []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "--", allowed, denied)
	cmd.Env = append(os.Environ(), helperEnv+"="+mode)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper %s: %v: %s", mode, err, out)
	}
	if _, err := os.Stat(filepath.Join(denied, "new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("denied dir got a new file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(allowed, "new")); err != nil {
		t.Fatalf("allowed dir has no new file: %v", err)
	}
	return string(out)
}

func TestRestrictWrites(t *testing.T) {
	runHelper(t, "restrict")
}

func TestExec(t *testing.T) {
	out := runHelper(t, "exec")
	if !strings.Contains(out, "before") {
		t.Fatalf("restricted shell could not read the denied dir: %q", out)
	}
}
