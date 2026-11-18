package vcs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/fnune/doriath/internal/fswatch"
)

// Commondir is the file that sends git from a store to another one, with
// its config and hooks. Only a linked worktree's admin directory has one.
const Commondir = "commondir"

// placeholderCommondir is what doriath once wrote to hold the name in a
// store. libgit2, and so nix, reads it as a broken worktree.
var placeholderCommondir = []byte(".\n")

// RootGuard removes a commondir from git stores whose root the jail can
// write, when a store is added, as soon as one appears, and when the guard
// closes, since git on your machine would follow it while the session runs.
type RootGuard struct {
	mu   sync.Mutex
	fw   *fswatch.Watcher
	all  []string
	w    io.Writer
	done chan struct{}
	stop context.CancelFunc
	once sync.Once
}

// NewRootGuard returns a guard that sweeps only on Add and Close, with the
// error, when the kernel cannot watch the stores.
func NewRootGuard(w io.Writer) (*RootGuard, error) {
	ctx, stop := context.WithCancel(context.Background())
	g := &RootGuard{w: &lockedWriter{w: w}, done: make(chan struct{}), stop: stop}
	fw, err := fswatch.New()
	if err != nil {
		close(g.done)
		return g, err
	}
	g.fw = fw
	go func() {
		defer close(g.done)
		fw.Run(ctx, func(ev fswatch.Event) {
			if ev.Name == Commondir {
				g.sweep(ev.Dir)
			}
		})
	}()
	return g, nil
}

func (g *RootGuard) Add(roots ...string) {
	for _, root := range roots {
		g.mu.Lock()
		g.all = append(g.all, root)
		g.mu.Unlock()
		if g.fw != nil {
			_ = g.fw.Add(root, unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_CLOSE_WRITE)
		}
		g.sweep(root)
	}
}

func (g *RootGuard) Close() {
	g.once.Do(func() {
		g.stop()
		<-g.done
		if g.fw != nil {
			_ = g.fw.Close()
		}
		g.mu.Lock()
		all := g.all
		g.mu.Unlock()
		for _, root := range all {
			g.sweep(root)
		}
	})
}

func (g *RootGuard) sweep(root string) {
	p := filepath.Join(root, Commondir)
	info, err := os.Lstat(p)
	if err != nil {
		return
	}
	data, _ := os.ReadFile(p)
	if err := os.RemoveAll(p); err != nil {
		fmt.Fprintf(g.w, "could not remove %s, which sends git on your machine to another repository: %v\n", p, err)
		return
	}
	if !info.Mode().IsRegular() || !bytes.Equal(data, placeholderCommondir) {
		fmt.Fprintf(g.w, "removed %s, which sent git on your machine to another repository\n", p)
	}
}
