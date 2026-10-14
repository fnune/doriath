// Package promote makes a path writable in a running jail, without
// restarting it.
//
// bubblewrap nests the jail's processes in a child user namespace, and the
// jail's mount namespace belongs to the parent. A helper enters that parent
// and the mount namespace, and changes mounts with the new mount API. The
// jail's own processes stay in the child, so the mounts it adds are locked
// for them.
package promote

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type Request struct {
	// Reaper is the pid, on the host, of the jail's first process.
	Reaper int
	// JailExe is girdle's binary as the jail sees it. The helper runs it in
	// the jail's mount namespace, so it must be a path the agent cannot
	// replace.
	JailExe string
	// HostExe is girdle's binary on the host, for the helper that opens a
	// host directory the jail cannot see.
	HostExe string
	Nsenter string
	Unshare string
	Path    string
	// Visible says the path is inside one of the jail's mounts. Otherwise
	// the helper mounts the host directory there.
	Visible bool
}

// Writable makes r.Path writable in the jail.
func Writable(ctx context.Context, r Request) error {
	if r.Visible {
		return enter(ctx, r, nil, "writable", r.Path)
	}
	tree, err := openHostTree(ctx, r)
	if err != nil {
		return err
	}
	defer tree.Close()
	return enter(ctx, r, []*os.File{tree}, "attach", r.Path)
}

func enter(ctx context.Context, r Request, extra []*os.File, args ...string) error {
	userNS, err := os.Open("/proc/" + strconv.Itoa(r.Reaper) + "/ns/user")
	if err != nil {
		return err
	}
	defer userNS.Close()
	parent, err := unix.IoctlRetInt(int(userNS.Fd()), unix.NS_GET_PARENT)
	if err != nil {
		return fmt.Errorf("find the jail's mount owner: %w", err)
	}
	owner := os.NewFile(uintptr(parent), "owner")
	defer owner.Close()
	cmd := exec.CommandContext(ctx, r.Nsenter, append([]string{
		"--user=/proc/self/fd/3", "--mount=/proc/" + strconv.Itoa(r.Reaper) + "/ns/mnt",
		"--preserve-credentials", "--keep-caps", "--", r.JailExe, "__promote",
	}, args...)...)
	cmd.ExtraFiles = append([]*os.File{owner}, extra...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// openHostTree clones a host directory in a user namespace of its own,
// which can see host paths and may clone mounts, and receives the clone.
func openHostTree(ctx context.Context, r Request) (*os.File, error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	ours, theirs := os.NewFile(uintptr(pair[0]), "ours"), os.NewFile(uintptr(pair[1]), "theirs")
	defer ours.Close()
	cmd := exec.CommandContext(ctx, r.Unshare, "-U", "-m", "-r", "--", r.HostExe, "__promote", "open", r.Path)
	cmd.ExtraFiles = []*os.File{theirs}
	out, err := cmd.CombinedOutput()
	_ = theirs.Close()
	if err != nil {
		return nil, fmt.Errorf("open %s: %w: %s", r.Path, err, strings.TrimSpace(string(out)))
	}
	fd, err := receive(int(ours.Fd()))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "tree"), nil
}

// Inner runs girdle __promote, inside the namespaces enter or openHostTree
// set up.
func Inner(args []string) error {
	if len(args) != 2 {
		return errors.New("__promote: want an operation and a path")
	}
	op, path := args[0], args[1]
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("__promote: %q is not an absolute clean path", path)
	}
	switch op {
	case "writable":
		return writableInPlace(path)
	case "open":
		return sendTree(path)
	case "attach":
		return attach(path)
	}
	return fmt.Errorf("__promote: unknown operation %q", op)
}

func openNoSymlinks(dir int, path string, flags uint64) (int, error) {
	return unix.Openat2(dir, path, &unix.OpenHow{
		Flags:   flags | unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
}

var clearReadOnly = unix.MountAttr{Attr_clr: unix.MOUNT_ATTR_RDONLY}

// writableInPlace clears read-only on the mount rooted at path, which every
// process in the jail sees at once. For a path inside a mount, it stacks a
// writable clone of that subtree, mounts below it included, so the guards
// and hidden paths inside keep their own mounts.
func writableInPlace(path string) error {
	fd, err := openNoSymlinks(unix.AT_FDCWD, path, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = unix.Close(fd) }()
	err = unix.MountSetattr(fd, "", unix.AT_EMPTY_PATH, &clearReadOnly)
	if err == nil || !errors.Is(err, unix.EINVAL) {
		return err
	}
	tree, err := unix.OpenTree(fd, "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH|unix.AT_RECURSIVE)
	if err != nil {
		return fmt.Errorf("clone %s: %w", path, err)
	}
	defer func() { _ = unix.Close(tree) }()
	if err := unix.MountSetattr(tree, "", unix.AT_EMPTY_PATH, &clearReadOnly); err != nil {
		return fmt.Errorf("clear read-only on %s: %w", path, err)
	}
	return unix.MoveMount(tree, "", fd, "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH)
}

func sendTree(path string) error {
	fd, err := openNoSymlinks(unix.AT_FDCWD, path, unix.O_DIRECTORY)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	tree, err := unix.OpenTree(fd, "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH|unix.AT_RECURSIVE)
	if err != nil {
		return fmt.Errorf("clone %s: %w", path, err)
	}
	return unix.Sendmsg(3, []byte{0}, unix.UnixRights(tree), nil, 0)
}

func receive(sock int) (int, error) {
	buf, oob := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(sock, buf, oob, 0)
	if err != nil {
		return 0, err
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, fmt.Errorf("receive the mount: %w", err)
	}
	if len(msgs) == 0 {
		return 0, errors.New("no mount received")
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil {
		return 0, fmt.Errorf("receive the mount: %w", err)
	}
	if len(fds) == 0 {
		return 0, errors.New("no mount received")
	}
	return fds[0], nil
}

// attach mounts the host directory received as fd 4 at path, creating the
// directories on the way without following symlinks.
func attach(path string) error {
	target, err := mkdirNoSymlinks(path)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(target) }()
	_ = unix.MountSetattr(4, "", unix.AT_EMPTY_PATH, &clearReadOnly)
	return unix.MoveMount(4, "", target, "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH)
}

func mkdirNoSymlinks(path string) (int, error) {
	dir, err := openNoSymlinks(unix.AT_FDCWD, "/", unix.O_DIRECTORY)
	if err != nil {
		return 0, err
	}
	for _, name := range strings.Split(strings.Trim(path, "/"), "/") {
		next, err := openNoSymlinks(dir, name, unix.O_DIRECTORY)
		if errors.Is(err, unix.ENOENT) {
			if err := unix.Mkdirat(dir, name, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
				_ = unix.Close(dir)
				return 0, fmt.Errorf("create %s in %s: %w", name, path, err)
			}
			next, err = openNoSymlinks(dir, name, unix.O_DIRECTORY)
		}
		_ = unix.Close(dir)
		if err != nil {
			return 0, fmt.Errorf("open %s in %s: %w", name, path, err)
		}
		dir = next
	}
	return dir, nil
}
