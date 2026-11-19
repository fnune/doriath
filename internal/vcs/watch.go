package vcs

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/fnune/doriath/internal/fswatch"
)

// Watch repairs the worktrees the agent adds while the session runs, as
// soon as their pointers change, instead of only when it ends. Until the
// end step, git on your machine would otherwise follow what the agent wrote
// into a worktree's admin directory or its .git file. Removing a worktree
// still works. Watch returns when ctx ends; w gets a line for each repair.
func Watch(ctx context.Context, rec *Record, w io.Writer) error {
	fw, err := fswatch.New()
	if err != nil {
		return err
	}
	defer func() { _ = fw.Close() }()
	wt := &watcher{fw: fw, rec: rec, w: &lockedWriter{w: w}, dirs: map[string]watched{}}
	for i := range rec.Repos {
		r := &rec.Repos[i]
		wt.add(filepath.Join(r.GitDir, "worktrees"), watched{repo: r, kind: kindWorktrees})
		for _, name := range listWorktrees(r.GitDir) {
			if !slices.Contains(r.Worktrees, name) {
				wt.adopt(r, name)
			}
		}
	}
	fw.Run(ctx, wt.handle)
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
	fw   *fswatch.Watcher
	rec  *Record
	w    io.Writer
	dirs map[string]watched
}

func (wt *watcher) add(dir string, what watched) {
	if wt.fw.Add(dir, unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_MODIFY|unix.IN_CLOSE_WRITE|unix.IN_DELETE) == nil {
		wt.dirs[dir] = what
	}
}

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

func (wt *watcher) handle(ev fswatch.Event) {
	what, ok := wt.dirs[ev.Dir]
	if !ok {
		return
	}
	switch what.kind {
	case kindWorktrees:
		if ev.Mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0 {
			wt.adopt(what.repo, ev.Name)
		}
	case kindAdmin:
		if ev.Name == "commondir" || ev.Name == "gitdir" || ev.Name == "config.worktree" {
			wt.repair(what.repo, what.admin)
		}
	case kindCheckout:
		if ev.Name == ".git" {
			wt.repair(what.repo, what.admin)
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
