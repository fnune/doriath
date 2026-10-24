// Package fswatch reports the names that change in watched folders, through
// inotify.
package fswatch

import (
	"context"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Event is a name that changed in a watched folder.
type Event struct {
	Dir  string
	Name string
	Mask uint32
}

type Watcher struct {
	fd   int
	mu   sync.Mutex
	dirs map[int32]string
}

func New() (*Watcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	return &Watcher{fd: fd, dirs: map[int32]string{}}, nil
}

// Add watches dir for the events of mask, such as unix.IN_CREATE. Another
// Add of the same folder replaces its mask.
func (w *Watcher) Add(dir string, mask uint32) error {
	wd, err := unix.InotifyAddWatch(w.fd, dir, mask)
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.dirs[int32(wd)] = dir
	w.mu.Unlock()
	return nil
}

// Run calls handle for each event until ctx ends. It checks ctx a few
// times a second.
func (w *Watcher) Run(ctx context.Context, handle func(Event)) {
	buf := make([]byte, 64*(unix.SizeofInotifyEvent+unix.NAME_MAX+1))
	fds := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN}}
	for ctx.Err() == nil {
		if n, _ := unix.Poll(fds, 200); n <= 0 {
			continue
		}
		n, err := unix.Read(w.fd, buf)
		if err != nil {
			continue
		}
		for _, ev := range w.parse(buf[:n]) {
			handle(ev)
		}
	}
}

func (w *Watcher) parse(buf []byte) []Event {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []Event
	for len(buf) >= unix.SizeofInotifyEvent {
		ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[0]))
		end := min(unix.SizeofInotifyEvent+int(ev.Len), len(buf))
		name := trimNul(buf[unix.SizeofInotifyEvent:end])
		buf = buf[end:]
		if dir, ok := w.dirs[ev.Wd]; ok {
			out = append(out, Event{Dir: dir, Name: name, Mask: ev.Mask})
		}
	}
	return out
}

func trimNul(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// Close stops the watches. Call it after Run returns.
func (w *Watcher) Close() error { return unix.Close(w.fd) }
