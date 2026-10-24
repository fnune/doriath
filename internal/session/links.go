package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

const linkEvents = unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_ATTRIB

type linkKeeper struct {
	mu      sync.Mutex
	targets map[string]string
	watches map[int]string
	watched map[string]bool
	fd      int
	done    chan struct{}
	stopped chan struct{}
	report  func(path, found string)
}

func newLinkKeeper(report func(path, found string)) *linkKeeper {
	return &linkKeeper{targets: map[string]string{}, watches: map[int]string{}, watched: map[string]bool{}, fd: -1, report: report}
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
	if k.fd < 0 {
		fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
		if err != nil {
			return err
		}
		k.fd, k.done, k.stopped = fd, make(chan struct{}), make(chan struct{})
		go k.loop(fd)
	}
	wd, err := unix.InotifyAddWatch(k.fd, dir, linkEvents|unix.IN_DONT_FOLLOW)
	if err != nil {
		return err
	}
	k.watches[wd] = dir
	k.watched[dir] = true
	return nil
}

func (k *linkKeeper) loop(fd int) {
	defer close(k.stopped)
	buf := make([]byte, 64*(unix.SizeofInotifyEvent+unix.NAME_MAX+1))
	for {
		select {
		case <-k.done:
			return
		default:
		}
		ready, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 200)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return
		}
		if ready == 0 {
			continue
		}
		n, err := unix.Read(fd, buf)
		if err != nil {
			continue
		}
		for _, path := range k.changed(buf[:n]) {
			k.restore(path)
		}
	}
}

func (k *linkKeeper) changed(buf []byte) []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []string
	for off := 0; off+unix.SizeofInotifyEvent <= len(buf); {
		ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
		nameStart := off + unix.SizeofInotifyEvent
		nameEnd := min(nameStart+int(ev.Len), len(buf))
		name := string(trimNul(buf[nameStart:nameEnd]))
		off = nameEnd
		dir, ok := k.watches[int(ev.Wd)]
		if !ok || name == "" {
			continue
		}
		path := filepath.Join(dir, name)
		if _, kept := k.targets[path]; kept && !slices.Contains(out, path) {
			out = append(out, path)
		}
	}
	return out
}

func trimNul(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
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
	found, err := os.Readlink(path)
	if err == nil && found == target {
		return
	}
	switch {
	case errors.Is(err, os.ErrNotExist):
		found = "nothing"
	case err != nil:
		found = "a file or folder"
	default:
		found = "a link to " + found
	}
	if err := os.RemoveAll(path); err != nil {
		k.report(path, found+", and doriath could not remove it: "+err.Error())
		return
	}
	if err := os.Symlink(target, path); err != nil {
		k.report(path, found+", and doriath could not put the link back: "+err.Error())
		return
	}
	k.report(path, found)
}

func (k *linkKeeper) Close() {
	k.mu.Lock()
	fd, done, stopped := k.fd, k.done, k.stopped
	k.fd = -1
	k.mu.Unlock()
	if fd < 0 {
		return
	}
	close(done)
	<-stopped
	_ = unix.Close(fd)
}

func (s *Session) linkRestored(path, found string) {
	reason := Printable("the jail changed it to " + found + ", and doriath put the link back")
	s.egress.Block(path, reason)
	s.log.Write("link-restored", map[string]string{"path": path, "found": found})
	if s.deps.Informer != nil {
		_ = s.deps.Informer.Inform("doriath put back "+filepath.Base(path), Printable(path+": "+reason))
	}
}
