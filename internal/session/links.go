package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/fnune/doriath/internal/fswatch"
)

const linkEvents = unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_ATTRIB

type linkKeeper struct {
	mu      sync.Mutex
	targets map[string]string
	watched map[string]bool
	fw      *fswatch.Watcher
	stop    context.CancelFunc
	stopped chan struct{}
	report  func(path, found string)
	rootOf  func(path string) string
}

func newLinkKeeper(report func(path, found string)) *linkKeeper {
	return &linkKeeper{targets: map[string]string{}, watched: map[string]bool{}, report: report}
}

func (k *linkKeeper) Keep(paths ...string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, path := range paths {
		if _, ok := k.targets[path]; ok {
			continue
		}
		target, err := os.Readlink(path)
		if err != nil {
			return fmt.Errorf("keep the link %s: %w", path, err)
		}
		if err := k.watch(filepath.Dir(path)); err != nil {
			return fmt.Errorf("keep the link %s: %w", path, err)
		}
		k.targets[path] = target
	}
	return nil
}

func (k *linkKeeper) watch(dir string) error {
	if k.watched[dir] {
		return nil
	}
	if k.fw == nil {
		fw, err := fswatch.New()
		if err != nil {
			return err
		}
		ctx, stop := context.WithCancel(context.Background())
		k.fw, k.stop, k.stopped = fw, stop, make(chan struct{})
		go func() {
			defer close(k.stopped)
			fw.Run(ctx, k.changed)
		}()
	}
	if err := k.fw.Add(dir, linkEvents|unix.IN_DONT_FOLLOW); err != nil {
		return err
	}
	k.watched[dir] = true
	return nil
}

func (k *linkKeeper) changed(ev fswatch.Event) {
	if ev.Name == "" {
		return
	}
	path := filepath.Join(ev.Dir, ev.Name)
	k.mu.Lock()
	_, kept := k.targets[path]
	k.mu.Unlock()
	if kept {
		k.restore(path)
	}
}

func (k *linkKeeper) Check() {
	k.mu.Lock()
	paths := make([]string, 0, len(k.targets))
	for path := range k.targets {
		paths = append(paths, path)
	}
	k.mu.Unlock()
	slices.Sort(paths)
	for _, path := range paths {
		k.restore(path)
	}
}

func (k *linkKeeper) restore(path string) {
	k.mu.Lock()
	target := k.targets[path]
	k.mu.Unlock()
	root := filepath.Dir(path)
	if k.rootOf != nil {
		root = k.rootOf(path)
	}
	if root == "" {
		k.report(path, "a folder that holds a link, and no writable folder of the profile holds it, so doriath could not put the link back safely")
		return
	}
	parent, name, err := openParentBeneath(root, path)
	if err != nil {
		k.report(path, "a folder that holds a link, and doriath could not put the link back: "+err.Error())
		return
	}
	defer parent.Close()
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(int(parent.Fd()), name, buf)
	if err == nil && string(buf[:n]) == target {
		return
	}
	found := "a file or folder"
	switch {
	case errors.Is(err, os.ErrNotExist):
		found = "nothing"
	case err == nil:
		found = "a link to " + string(buf[:n])
	}
	if err := os.RemoveAll(viaDescriptor(parent, name)); err != nil {
		k.report(path, found+", and doriath could not remove it: "+err.Error())
		return
	}
	if err := unix.Symlinkat(target, int(parent.Fd()), name); err != nil {
		k.report(path, found+", and doriath could not put the link back: "+err.Error())
		return
	}
	k.report(path, found)
}

func (k *linkKeeper) Close() {
	k.mu.Lock()
	fw, stop, stopped := k.fw, k.stop, k.stopped
	k.fw = nil
	k.mu.Unlock()
	if fw == nil {
		return
	}
	stop()
	<-stopped
	_ = fw.Close()
}

func (s *Session) linkRestored(path, found string) {
	reason := Printable("the jail changed it to " + found + ", and doriath put the link back")
	s.egress.Block(path, reason)
	s.log.Write("link-restored", map[string]string{"path": path, "found": found})
	if s.deps.Informer != nil {
		_ = s.deps.Informer.Inform(s.id, "doriath put back "+filepath.Base(path), Printable(path+": "+reason))
	}
}
