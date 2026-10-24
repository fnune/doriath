package promote

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestInnerRefusesMalformedArguments(t *testing.T) {
	for _, c := range []struct {
		name    string
		args    []string
		refusal string
	}{
		{"no arguments", nil, "want an operation, a path and its guards"},
		{"no path", []string{"writable"}, "want an operation, a path and its guards"},
		{"a guard outside the path", []string{"writable", "/a", "/b"}, "guard /b is not inside /a"},
		{"a guard that is not clean", []string{"writable", "/a", "/a/b/"}, "not an absolute clean path"},
		{"guards for attach", []string{"attach", "/a", "/a/b"}, "attach takes its guards from the tree it receives"},
		{"a relative path", []string{"writable", "a/b"}, "not an absolute clean path"},
		{"a path that climbs", []string{"writable", "/a/../etc"}, "not an absolute clean path"},
		{"a trailing slash", []string{"writable", "/a/"}, "not an absolute clean path"},
		{"an unknown operation", []string{"chmod", "/a"}, `unknown operation "chmod"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := Inner(c.args); err == nil || !strings.Contains(err.Error(), c.refusal) {
				t.Fatalf("Inner(%q) = %v, want %q", c.args, err, c.refusal)
			}
		})
	}
}

func TestMkdirNoSymlinksCreatesTheMissingDirectories(t *testing.T) {
	path := filepath.Join(realTempDir(t), "a", "b")
	fd, err := mkdirNoSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if !sameFile(t, fd, path) {
		t.Fatalf("the descriptor is not %s", path)
	}
	again, err := mkdirNoSymlinks(path)
	if err != nil {
		t.Fatalf("an existing directory: %v", err)
	}
	_ = unix.Close(again)
}

// The jail can write the directories on the way to a granted path, so a
// symlink there must not redirect the mount to a place of the agent's
// choosing.
func TestMkdirNoSymlinksRefusesASymlinkOnTheWay(t *testing.T) {
	dir := realTempDir(t)
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := mkdirNoSymlinks(filepath.Join(dir, "link", "b")); !errors.Is(err, unix.ELOOP) {
		t.Fatalf("err = %v, want ELOOP", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "link", "b")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a directory was created behind the symlink")
	}
}

func TestPromotionRefusesASymlinkAsTheTarget(t *testing.T) {
	dir := realTempDir(t)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	for name, op := range map[string]func(string) error{"writable": writableInPlace, "open": sendTree, "attach": func(p string) error { return attach(p, false) }, "attach-read": func(p string) error { return attach(p, true) }} {
		if err := op(link); !errors.Is(err, unix.ELOOP) {
			t.Errorf("%s: err = %v, want ELOOP", name, err)
		}
	}
}

func TestReceiveTakesTheDescriptorSent(t *testing.T) {
	ours, theirs := socketpair(t)
	f, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := unix.Sendmsg(theirs, []byte{0}, unix.UnixRights(int(f.Fd())), nil, 0); err != nil {
		t.Fatal(err)
	}
	fd, err := receive(ours)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if !sameFile(t, fd, f.Name()) {
		t.Fatal("received another file")
	}
}

func TestReceiveRefusesAMessageWithoutADescriptor(t *testing.T) {
	ours, theirs := socketpair(t)
	if _, err := unix.Write(theirs, []byte{0}); err != nil {
		t.Fatal(err)
	}
	if _, err := receive(ours); err == nil || !strings.Contains(err.Error(), "no mount received") {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenHostTreeReportsTheHelpersOutput(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "unshare")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\necho 'unshare: user namespaces are disabled' >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := openHostTree(t.Context(), Request{Unshare: helper, HostExe: "/doriath", Path: "/home/u/videos"})
	if err == nil || !strings.Contains(err.Error(), "open /home/u/videos") || !strings.Contains(err.Error(), "user namespaces are disabled") {
		t.Fatalf("err = %v", err)
	}
}

func TestWritableInPlaceClearsReadOnlyOnAMountRoot(t *testing.T) {
	inMountNamespace(t, func(t *testing.T) {
		ro := readOnlyMount(t)
		if err := writableInPlace(ro); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(ro, "x"))
	})
}

func TestWritableInPlaceStacksAWritableSubtree(t *testing.T) {
	inMountNamespace(t, func(t *testing.T) {
		dir := realTempDir(t)
		sub := filepath.Join(dir, "sub")
		hidden := filepath.Join(sub, "hidden")
		if err := os.MkdirAll(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(hidden, []byte("key"), 0o600); err != nil {
			t.Fatal(err)
		}
		ro := readOnlyBind(t, dir)
		hideWithEmptyFile(t, hidden)
		if err := writableInPlace(sub); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Unmount(sub, unix.MNT_DETACH) })
		mustWrite(t, filepath.Join(sub, "x"))
		if err := os.WriteFile(filepath.Join(ro, "y"), nil, 0o600); !errors.Is(err, syscall.EROFS) {
			t.Fatalf("the rest of the mount became writable: %v", err)
		}
		if data, err := os.ReadFile(hidden); err != nil || len(data) != 0 {
			t.Errorf("a mount below the path was lost, and the hidden file shows %q: %v", data, err)
		}
	})
}

func TestSendTreeAndAttachMountAHostDirectory(t *testing.T) {
	inMountNamespace(t, func(t *testing.T) {
		dir := realTempDir(t)
		if err := os.WriteFile(filepath.Join(dir, "clip"), []byte("host"), 0o600); err != nil {
			t.Fatal(err)
		}
		src := readOnlyBind(t, dir)
		ours, theirs := socketpair(t)
		// sendTree writes to fd 3 and attach reads fd 4, as the helpers
		// receive them; the parent reserved both for this test.
		if err := unix.Dup3(theirs, 3, 0); err != nil {
			t.Fatal(err)
		}
		if err := sendTree(src); err != nil {
			t.Fatal(err)
		}
		tree, err := receive(ours)
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Dup3(tree, 4, 0); err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(tree)
		target := filepath.Join(realTempDir(t), "a", "videos")
		if err := attach(target, false); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Unmount(target, unix.MNT_DETACH) })
		if data, err := os.ReadFile(filepath.Join(target, "clip")); err != nil || string(data) != "host" {
			t.Fatalf("attached directory: %q, %v", data, err)
		}
		mustWrite(t, filepath.Join(target, "new"))
		if _, err := os.Stat(filepath.Join(dir, "new")); err != nil {
			t.Errorf("a write through the mount did not reach the host directory: %v", err)
		}
	})
}

const childEnv = "DORIATH_PROMOTE_TEST_CHILD"

// inMountNamespace runs body in a copy of the test binary that owns a user
// and mount namespace of its own, where it may change mounts as the helpers
// do in the jail. Machines without unprivileged user namespaces skip it.
func inMountNamespace(t *testing.T, body func(t *testing.T)) {
	t.Helper()
	if os.Getenv(childEnv) == t.Name() {
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			t.Fatal(err)
		}
		body(t)
		return
	}
	var reserved []*os.File
	for range 2 {
		f, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		reserved = append(reserved, f)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"="+t.Name())
	cmd.ExtraFiles = reserved
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err != nil && !errors.As(err, &exit):
		t.Skipf("no unprivileged user namespaces: %v", err)
	case err != nil:
		t.Fatalf("%v:\n%s", err, out)
	case !strings.Contains(string(out), "--- PASS: "+t.Name()):
		t.Fatalf("the child did not run the test:\n%s", out)
	}
}

// readOnlyMount is a read-only bind mount of a fresh directory with a
// subdirectory, as the jail mounts a read-only path.
func readOnlyMount(t *testing.T) string {
	t.Helper()
	dir := realTempDir(t)
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	return readOnlyBind(t, dir)
}

func readOnlyBind(t *testing.T, dir string) string {
	t.Helper()
	if err := unix.Mount(dir, dir, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(dir, unix.MNT_DETACH) })
	if err := unix.Mount("", dir, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "probe"), nil, 0o600); !errors.Is(err, syscall.EROFS) {
		t.Fatalf("the mount is not read-only: %v", err)
	}
	return dir
}

// hideWithEmptyFile mounts an empty file over path, as the jail hides one.
func hideWithEmptyFile(t *testing.T, path string) {
	t.Helper()
	empty := filepath.Join(realTempDir(t), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(empty, path, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(path, unix.MNT_DETACH) })
}

func mustWrite(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func socketpair(t *testing.T) (ours, theirs int) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(pair[0]); _ = unix.Close(pair[1]) })
	return pair[0], pair[1]
}

func sameFile(t *testing.T, fd int, path string) bool {
	t.Helper()
	var got, want unix.Stat_t
	if err := unix.Fstat(fd, &got); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(path, &want); err != nil {
		t.Fatal(err)
	}
	return got.Dev == want.Dev && got.Ino == want.Ino
}

// realTempDir resolves the temporary directory, since the helpers refuse
// every symlink and TMPDIR may be one.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAttachReadOnlyShowsAHostDirectoryThatTheJailCannotWrite(t *testing.T) {
	inMountNamespace(t, func(t *testing.T) {
		dir := realTempDir(t)
		if err := os.WriteFile(filepath.Join(dir, "notes"), []byte("host"), 0o600); err != nil {
			t.Fatal(err)
		}
		ours, theirs := socketpair(t)
		if err := unix.Dup3(theirs, 3, 0); err != nil {
			t.Fatal(err)
		}
		if err := sendTree(dir); err != nil {
			t.Fatal(err)
		}
		tree, err := receive(ours)
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Dup3(tree, 4, 0); err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(tree)
		target := filepath.Join(realTempDir(t), "a", "notes")
		if err := attach(target, true); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Unmount(target, unix.MNT_DETACH) })
		if data, err := os.ReadFile(filepath.Join(target, "notes")); err != nil || string(data) != "host" {
			t.Fatalf("attached directory: %q, %v", data, err)
		}
		if err := os.WriteFile(filepath.Join(target, "new"), []byte("x"), 0o600); !errors.Is(err, unix.EROFS) {
			t.Errorf("write = %v, want EROFS", err)
		}
	})
}
