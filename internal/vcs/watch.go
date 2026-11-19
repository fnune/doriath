package vcs

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/fnune/doriath/internal/fswatch"
)

// Watch repairs the worktrees the agent adds while the session runs, as
// soon as their pointers change, instead of only when it ends. Until the
// end step, git on your machine would otherwise follow what the agent wrote
// into a worktree's admin directory or its .git file. Removing a worktree
// still works. Watch returns when ctx ends; w gets a line for each repair.
func Watch(ctx context.Context, t Tools, rec *Record, w io.Writer) error {
	fw, err := fswatch.New()
	if err != nil {
		return err
	}
	defer func() { _ = fw.Close() }()
	wt := &watcher{fw: fw, t: t, rec: rec, w: &lockedWriter{w: w}, dirs: map[string]watched{}, now: time.Now}
	fw.Idle = wt.idle
	for i := range rec.Repos {
		r := &rec.Repos[i]
		wt.addMask(r.GitDir, unix.IN_CREATE|unix.IN_MOVED_TO, watched{repo: r, kind: kindStore})
		wt.addMask(filepath.Join(r.GitDir, "modules"), unix.IN_CREATE|unix.IN_MOVED_TO, watched{repo: r, kind: kindModules})
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
	kindStore
	kindModules
)

const nestedQuiet = 300 * time.Millisecond

type watched struct {
	repo  *Repo
	kind  kind
	admin string
}

type watcher struct {
	fw    *fswatch.Watcher
	t     Tools
	rec   *Record
	w     io.Writer
	dirs  map[string]watched
	now   func() time.Time
	dirty time.Time
}

func (wt *watcher) add(dir string, what watched) {
	wt.addMask(dir, unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_MODIFY|unix.IN_CLOSE_WRITE|unix.IN_DELETE, what)
}

func (wt *watcher) addMask(dir string, mask uint32, what watched) {
	if wt.fw.Add(dir, mask) == nil {
		wt.dirs[dir] = what
	}
}

func (wt *watcher) markNested() {
	if wt.dirty.IsZero() {
		wt.dirty = wt.now()
	}
}

func (wt *watcher) idle() {
	if !wt.dirty.IsZero() && wt.now().Sub(wt.dirty) >= nestedQuiet {
		wt.dirty = time.Time{}
		wt.setAsideNested()
	}
}

func (wt *watcher) setAsideNested() {
	ctx := context.Background()
	for i := range wt.rec.Repos {
		r := &wt.rec.Repos[i]
		_ = setAsideNewStores(r.GitDir, wt.rec, wt.w)
		_ = setAsideNestedGits(ctx, wt.t, r, wt.rec, wt.w)
	}
}

func (wt *watcher) resync() {
	for i := range wt.rec.Repos {
		r := &wt.rec.Repos[i]
		for _, name := range listWorktrees(r.GitDir) {
			if !slices.Contains(r.Worktrees, name) {
				wt.adopt(r, name)
			}
		}
	}
	wt.markNested()
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
	if ev.Overflowed() {
		wt.resync()
		return
	}
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
	case kindStore:
		switch ev.Name {
		case "index":
			wt.markNested()
		case "modules":
			wt.addMask(filepath.Join(what.repo.GitDir, "modules"), unix.IN_CREATE|unix.IN_MOVED_TO, watched{repo: what.repo, kind: kindModules})
			wt.markNested()
		}
	case kindModules:
		wt.markNested()
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
