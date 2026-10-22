package vcs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
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
	mu    sync.Mutex
	fd    int
	roots map[int32]string
	all   []string
	w     io.Writer
	done  chan struct{}
	stop  context.CancelFunc
	once  sync.Once
}

// NewRootGuard returns a guard that sweeps only on Add and Close, with the
// error, when the kernel cannot watch the stores.
func NewRootGuard(w io.Writer) (*RootGuard, error) {
	ctx, stop := context.WithCancel(context.Background())
	g := &RootGuard{fd: -1, roots: map[int32]string{}, w: &lockedWriter{w: w}, done: make(chan struct{}), stop: stop}
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		close(g.done)
		return g, err
	}
	g.fd = fd
	go g.run(ctx)
	return g, nil
}

func (g *RootGuard) Add(roots ...string) {
	for _, root := range roots {
		g.mu.Lock()
		g.all = append(g.all, root)
		if wd, err := unix.InotifyAddWatch(g.fd, root, unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_CLOSE_WRITE); err == nil {
			g.roots[int32(wd)] = root
		}
		g.mu.Unlock()
		g.sweep(root)
	}
}

// Close stops the guard after a last sweep of every store.
func (g *RootGuard) Close() {
	g.once.Do(func() {
		g.stop()
		<-g.done
		if g.fd >= 0 {
			_ = unix.Close(g.fd)
		}
		g.mu.Lock()
		all := g.all
		g.mu.Unlock()
		for _, root := range all {
			g.sweep(root)
		}
	})
}

func (g *RootGuard) run(ctx context.Context) {
	defer close(g.done)
	buf := make([]byte, 16*1024)
	fds := []unix.PollFd{{Fd: int32(g.fd), Events: unix.POLLIN}}
	for ctx.Err() == nil {
		if n, _ := unix.Poll(fds, 250); n <= 0 {
			continue
		}
		n, err := unix.Read(g.fd, buf)
		if err != nil {
			continue
		}
		for b := buf[:n]; len(b) >= unix.SizeofInotifyEvent; {
			ev := (*unix.InotifyEvent)(unsafe.Pointer(&b[0]))
			size := unix.SizeofInotifyEvent + int(ev.Len)
			if size > len(b) {
				break
			}
			name := strings.TrimRight(string(b[unix.SizeofInotifyEvent:size]), "\x00")
			b = b[size:]
			g.mu.Lock()
			root, ok := g.roots[ev.Wd]
			g.mu.Unlock()
			if ok && name == Commondir {
				g.sweep(root)
			}
		}
	}
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
