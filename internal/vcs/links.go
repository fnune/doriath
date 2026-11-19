package vcs

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var storeFolders = []string{"worktrees", "lfs", "modules", "logs", "refs", "rr-cache", "objects", "rebase-merge", "rebase-apply", "sequencer"}

const maxModuleDepth = 8

func storeLinks(gitDir string) map[string]string {
	links := map[string]string{}
	for _, name := range storeFolders {
		if target, err := os.Readlink(filepath.Join(gitDir, name)); err == nil {
			links[name] = target
		}
	}
	return links
}

func (r *Repo) knownLinks(known map[string]string) {
	for name, target := range r.Links {
		known[filepath.Join(r.GitDir, name)] = target
	}
}

func fixStoreLinks(gitDir string, started map[string]string) (removed, restored []string, err error) {
	fd, err := unix.Open(gitDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	for _, name := range storeFolders {
		var st unix.Stat_t
		if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || st.Mode&unix.S_IFMT != unix.S_IFLNK {
			continue
		}
		want, had := started[name]
		if had {
			if target, err := readlinkAt(fd, name); err == nil && target == want {
				continue
			}
		}
		if err := unix.Unlinkat(fd, name, 0); err != nil {
			return removed, restored, err
		}
		if !had {
			removed = append(removed, name)
			continue
		}
		if err := unix.Symlinkat(want, fd, name); err != nil {
			return removed, restored, err
		}
		restored = append(restored, name)
	}
	return removed, restored, nil
}

func readlinkAt(fd int, name string) (string, error) {
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(fd, name, buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func linkNotes(gitDir string, removed, restored []string) []string {
	var notes []string
	for _, name := range removed {
		notes = append(notes, fmt.Sprintf("the agent made %s a link to another folder; doriath removed the link", filepath.Join(gitDir, name)))
	}
	for _, name := range restored {
		notes = append(notes, fmt.Sprintf("the agent pointed the link %s at another folder; doriath put it back", filepath.Join(gitDir, name)))
	}
	return notes
}

func openDirBeneath(root, rel string) (int, error) {
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer func() { _ = unix.Close(rootFD) }()
	return unix.Openat2(rootFD, rel, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
}

func listWorktrees(root string) []string {
	fd, err := openDirBeneath(root, "worktrees")
	if err != nil {
		return nil
	}
	dir := os.NewFile(uintptr(fd), "worktrees")
	defer dir.Close()
	names, _ := dir.Readdirnames(-1)
	return names
}

func readAt(dir int, name string) ([]byte, error) {
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 64<<10))
}

func takeAway(dir int, name string) error {
	err := unix.Unlinkat(dir, name, 0)
	if !errors.Is(err, unix.EISDIR) && !errors.Is(err, unix.EPERM) {
		return err
	}
	var suffix [4]byte
	_, _ = rand.Read(suffix[:])
	return unix.Renameat(dir, name, dir, fmt.Sprintf("%s.doriath-%x", name, suffix))
}

func hasLinkBelow(root, path string, known map[string]string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return false
	}
	p := root
	for part := range strings.SplitSeq(rel, string(filepath.Separator)) {
		p = filepath.Join(p, part)
		if target, err := os.Readlink(p); err == nil && known[p] != target {
			return true
		}
	}
	return false
}

func WorktreeCheckouts(store string) []string {
	var dirs []string
	for _, name := range listWorktrees(store) {
		admin := filepath.Join(store, "worktrees", name)
		data, err := os.ReadFile(filepath.Join(admin, "gitdir"))
		if err != nil {
			continue
		}
		dirs = append(dirs, filepath.Dir(resolve(admin, strings.TrimSpace(string(data)))))
	}
	return dirs
}
