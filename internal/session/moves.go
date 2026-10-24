package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/fnune/doriath/internal/fswatch"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/term"
)

type moveGuard struct {
	mu      sync.Mutex
	holds   []guardedHold
	dest    string
	fw      *fswatch.Watcher
	watched map[string]bool
	stop    context.CancelFunc
	stopped chan struct{}
	report  func(path, moved, reason string, err error)
}

type guardedHold struct {
	profile.PathHold
	root string
}

func newMoveGuard(holds []guardedHold, dest string, report func(path, moved, reason string, err error)) (*moveGuard, error) {
	g := &moveGuard{holds: holds, dest: dest, watched: map[string]bool{}, report: report}
	g.sweep()
	if len(holds) == 0 {
		return g, nil
	}
	fw, err := fswatch.New()
	if err != nil {
		return g, err
	}
	ctx, stop := context.WithCancel(context.Background())
	g.fw, g.stop, g.stopped = fw, stop, make(chan struct{})
	g.watchParents()
	go func() {
		defer close(g.stopped)
		fw.Run(ctx, func(fswatch.Event) {
			g.watchParents()
			g.sweep()
		})
	}()
	g.sweep()
	return g, nil
}

func (g *moveGuard) watchParents() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, h := range g.holds {
		for dir := filepath.Dir(h.Path); within(dir, h.root); dir = filepath.Dir(dir) {
			if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
				continue
			}
			if !g.watched[dir] && g.fw.Add(dir, unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_DONT_FOLLOW|unix.IN_ONLYDIR) == nil {
				g.watched[dir] = true
			}
			break
		}
	}
}

func (g *moveGuard) sweep() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, h := range g.holds {
		if _, err := os.Lstat(h.Path); err != nil {
			continue
		}
		moved, err := g.move(h)
		g.report(h.Path, moved, h.Reason, err)
	}
}

func (g *moveGuard) move(h guardedHold) (string, error) {
	rel, err := filepath.Rel(h.root, h.Path)
	if err != nil {
		return "", err
	}
	dest := filepath.Join(g.dest, rel)
	for i := 1; ; i++ {
		if _, err := os.Lstat(dest); errors.Is(err, fs.ErrNotExist) {
			break
		}
		dest = filepath.Join(g.dest, rel+"."+strconv.Itoa(i))
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return "", err
	}
	err = os.Rename(h.Path, dest)
	if errors.Is(err, unix.EXDEV) {
		if err = copyTree(h.Path, dest); err == nil {
			err = os.RemoveAll(h.Path)
		}
	}
	if err != nil {
		if removeErr := os.RemoveAll(h.Path); removeErr != nil {
			return "", fmt.Errorf("%w, and doriath could not remove it: %w", err, removeErr)
		}
		return "", fmt.Errorf("%w, so doriath removed it", err)
	}
	return dest, nil
}

func (g *moveGuard) Close() {
	if g.fw != nil {
		g.stop()
		<-g.stopped
		_ = g.fw.Close()
	}
	g.sweep()
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o700)
		case d.Type()&fs.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case d.Type().IsRegular():
			return copyRegular(path, target)
		}
		return nil
	})
}

func copyRegular(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func (s *Session) guardMissingHolds() {
	p := s.req.Profile
	var holds []guardedHold
	for _, h := range p.PathRules.Hold {
		if h.Missing != profile.MissingMove {
			continue
		}
		if _, err := os.Lstat(h.Path); !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		for _, m := range p.Mounts {
			if m.Mode == profile.ModeWrite && m.Path != h.Path && within(h.Path, m.Path) {
				holds = append(holds, guardedHold{PathHold: h, root: m.Path})
				break
			}
		}
	}
	g, err := newMoveGuard(holds, s.deps.Paths.Moved(s.id), s.heldMoved)
	s.closers = append(s.closers, g.Close)
	if err != nil {
		s.notes = append(s.notes, note{term.Warn, fmt.Sprintf("doriath moves out a file that the agent creates at a held path only when the session ends: %v", err)})
	}
}

func (s *Session) heldMoved(path, moved, reason string, err error) {
	what := "the jail created it, and doriath moved it to " + moved
	if err != nil {
		what = "the jail created it, and doriath could not move it: " + err.Error()
	}
	text := Printable(what + ". " + reason)
	s.egress.Block(path, text)
	s.log.Write("held-moved", map[string]string{"path": path, "moved": moved})
	if s.deps.Informer != nil {
		_ = s.deps.Informer.Inform("doriath moved "+filepath.Base(path)+" out of the repository", Printable(path+": "+text))
	}
}
