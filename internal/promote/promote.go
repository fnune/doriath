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

	"github.com/fnune/doriath/internal/jail"
)

type Request struct {
	Reaper int
	// JailExe is doriath's binary as the jail sees it. The helper runs it in
	// the jail's mount namespace, so it must be a path the agent cannot
	// replace.
	JailExe string
	// HostExe is doriath's binary on the host, for the helper that opens a
	// host directory the jail cannot see.
	HostExe string
	Nsenter string
	Unshare string
	Path    string
	Guards  []string
	Visible bool
	Dest    string
}

func Writable(ctx context.Context, r Request) error {
	if r.Visible {
		return enter(ctx, r, nil, append([]string{"writable", r.Path}, r.Guards...)...)
	}
	tree, err := openHostTree(ctx, r)
	if err != nil {
		return err
	}
	defer tree.Close()
	return enter(ctx, r, []*os.File{tree}, "attach", r.Path)
}

func Readable(ctx context.Context, r Request) error {
	tree, err := openHostTree(ctx, r)
	if err != nil {
		return err
	}
	defer tree.Close()
	dest := r.Path
	if r.Dest != "" {
		dest = r.Dest
	}
	return enter(ctx, r, []*os.File{tree}, "attach-read", dest)
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

func openHostTree(ctx context.Context, r Request) (*os.File, error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	ours, theirs := os.NewFile(uintptr(pair[0]), "ours"), os.NewFile(uintptr(pair[1]), "theirs")
	defer ours.Close()
	cmd := exec.CommandContext(ctx, r.Unshare, append([]string{"-U", "-m", "-r", "--", r.HostExe, "__promote", "open", r.Path}, r.Guards...)...)
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

func Inner(args []string) error {
	if len(args) < 2 {
		return errors.New("__promote: want an operation, a path and its guards")
	}
	op, path, guards := args[0], args[1], args[2:]
	for _, p := range args[1:] {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fmt.Errorf("__promote: %q is not an absolute clean path", p)
		}
	}
	for _, g := range guards {
		if !strings.HasPrefix(g, path+"/") {
			return fmt.Errorf("__promote: guard %s is not inside %s", g, path)
		}
	}
	switch op {
	case "writable":
		return writableInPlaceAfter(guards, path)
	case "open":
		return sendTreeWithGuards(guards, path)
	case "attach":
		if len(guards) > 0 {
			return errors.New("__promote: attach takes its guards from the tree it receives")
		}
		return attach(path, false)
	case "attach-read":
		if len(guards) > 0 {
			return errors.New("__promote: attach-read takes no guards")
		}
		return attach(path, true)
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

func writableInPlaceAfter(guards []string, path string) error {
	if err := guardAndPin(path, guards); err != nil {
		return err
	}
	return writableInPlace(path)
}

func sendTreeWithGuards(guards []string, path string) error {
	if err := guardAndPin(path, guards); err != nil {
		return err
	}
	return sendTree(path)
}

func guardAndPin(path string, guards []string) error {
	if err := readOnly(guards); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, g := range guards {
		for _, dir := range jail.Between(path, g) {
			if seen[dir] {
				continue
			}
			seen[dir] = true
			fd, err := openNoSymlinks(unix.AT_FDCWD, dir, unix.O_DIRECTORY)
			if err != nil {
				return fmt.Errorf("open %s: %w", dir, err)
			}
			err = pinWritable(fd)
			_ = unix.Close(fd)
			if err != nil {
				return fmt.Errorf("pin %s: %w", dir, err)
			}
		}
	}
	return nil
}

func pinWritable(fd int) error {
	tree, err := unix.OpenTree(fd, "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH|unix.AT_RECURSIVE)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(tree) }()
	if err := unix.MountSetattr(tree, "", unix.AT_EMPTY_PATH, &clearReadOnly); err != nil {
		return err
	}
	return unix.MoveMount(tree, "", fd, "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH)
}

var setReadOnly = unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY}

func readOnly(paths []string) error {
	for _, p := range paths {
		fd, err := openNoSymlinks(unix.AT_FDCWD, p, 0)
		if err != nil {
			return fmt.Errorf("open %s: %w", p, err)
		}
		err = bindReadOnly(fd)
		_ = unix.Close(fd)
		if err != nil {
			return fmt.Errorf("make %s read-only: %w", p, err)
		}
	}
	return nil
}

func bindReadOnly(fd int) error {
	tree, err := unix.OpenTree(fd, "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH|unix.AT_RECURSIVE)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(tree) }()
	if err := unix.MountSetattr(tree, "", unix.AT_EMPTY_PATH|unix.AT_RECURSIVE, &setReadOnly); err != nil {
		return err
	}
	return unix.MoveMount(tree, "", fd, "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH)
}

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

func attach(path string, readOnly bool) error {
	target, err := mkdirNoSymlinks(path)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(target) }()
	if readOnly {
		if err := unix.MountSetattr(4, "", unix.AT_EMPTY_PATH|unix.AT_RECURSIVE, &setReadOnly); err != nil {
			return fmt.Errorf("make %s read-only: %w", path, err)
		}
	} else {
		_ = unix.MountSetattr(4, "", unix.AT_EMPTY_PATH, &clearReadOnly)
	}
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
