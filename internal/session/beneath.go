package session

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func openParentBeneath(root, path string) (*os.File, string, error) {
	rel, err := filepath.Rel(root, filepath.Dir(path))
	if err != nil {
		return nil, "", err
	}
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", fmt.Errorf("open %s: %w", root, err)
	}
	defer func() { _ = unix.Close(rootFD) }()
	fd, err := unix.Openat2(rootFD, rel, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, "", fmt.Errorf("open %s below %s: %w", filepath.Dir(path), root, err)
	}
	return os.NewFile(uintptr(fd), "parent"), filepath.Base(path), nil
}

func viaDescriptor(dir *os.File, name string) string {
	return fmt.Sprintf("/proc/self/fd/%d/%s", dir.Fd(), name)
}

func presentIn(dir *os.File, name string) bool {
	var st unix.Stat_t
	return unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil
}
