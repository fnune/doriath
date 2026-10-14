package vcs

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Watch repairs the worktrees the agent adds while the session runs, as
// soon as their pointers change, instead of only when it ends. Until the
// end step, git on your machine would otherwise follow what the agent wrote
// into a worktree's admin directory or its .git file. Removing a worktree
// still works. Watch returns when ctx ends; w gets a line for each repair.
func Watch(ctx context.Context, rec *Record, w io.Writer) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	wt := &watcher{fd: fd, rec: rec, w: &lockedWriter{w: w}, dirs: map[int32]watched{}}
	for i := range rec.Repos {
		r := &rec.Repos[i]
		wt.add(filepath.Join(r.GitDir, "worktrees"), watched{repo: r, kind: kindWorktrees})
		for _, name := range entries(filepath.Join(r.GitDir, "worktrees")) {
			if !slices.Contains(r.Worktrees, name) {
				wt.adopt(r, name)
			}
		}
	}
	buf := make([]byte, 64*1024)
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for ctx.Err() == nil {
		if n, _ := unix.Poll(fds, 250); n <= 0 {
			continue
		}
		n, err := unix.Read(fd, buf)
		if err != nil {
			continue
		}
		wt.handle(buf[:n])
	}
	return nil
}

type kind int

const (
	kindWorktrees kind = iota
	kindAdmin
	kindCheckout
)

type watched struct {
	repo  *Repo
	kind  kind
	admin string
}

type watcher struct {
	fd   int
	rec  *Record
	w    io.Writer
	dirs map[int32]watched
}

func (wt *watcher) add(dir string, what watched) {
	wd, err := unix.InotifyAddWatch(wt.fd, dir, unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_MODIFY|unix.IN_CLOSE_WRITE|unix.IN_DELETE)
	if err == nil {
		wt.dirs[int32(wd)] = what
	}
}

// adopt watches a worktree the agent added, and repairs it now.
func (wt *watcher) adopt(r *Repo, name string) {
	admin := filepath.Join(r.GitDir, "worktrees", name)
	wt.add(admin, watched{repo: r, kind: kindAdmin, admin: admin})
	wt.repair(r, admin)
}

func (wt *watcher) repair(r *Repo, admin string) {
	_ = repairWorktree(admin, wt.rec, r.Path, wt.w, true)
	if data, err := os.ReadFile(filepath.Join(admin, "gitdir")); err == nil {
		checkout := filepath.Dir(resolve(admin, strings.TrimSpace(string(data))))
		if slices.ContainsFunc(wt.rec.Writable, func(root string) bool { return within(checkout, root) }) {
			wt.add(checkout, watched{repo: r, kind: kindCheckout, admin: admin})
		}
	}
}

func (wt *watcher) handle(buf []byte) {
	for len(buf) >= unix.SizeofInotifyEvent {
		ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[0]))
		size := unix.SizeofInotifyEvent + int(ev.Len)
		if size > len(buf) {
			return
		}
		name := strings.TrimRight(string(buf[unix.SizeofInotifyEvent:size]), "\x00")
		buf = buf[size:]
		what, ok := wt.dirs[ev.Wd]
		if !ok {
			continue
		}
		switch what.kind {
		case kindWorktrees:
			if ev.Mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0 {
				wt.adopt(what.repo, name)
			}
		case kindAdmin:
			if name == "commondir" || name == "gitdir" || name == "config.worktree" {
				wt.repair(what.repo, what.admin)
			}
		case kindCheckout:
			if name == ".git" {
				wt.repair(what.repo, what.admin)
			}
		}
	}
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
