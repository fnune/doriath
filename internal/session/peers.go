package session

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type hostPeers struct {
	init  atomic.Int64
	known chan struct{}
	once  sync.Once
	exe   string
}

func newHostPeers(exe string) *hostPeers {
	return &hostPeers{exe: exe, known: make(chan struct{})}
}

func (h *hostPeers) setInit(pid int) {
	h.init.Store(int64(pid))
	h.once.Do(func() { close(h.known) })
}

// initWait bounds how long a connection waits for the reaper's pid. Init can
// connect before the goroutine that reads bubblewrap's info has run, and
// refusing its header then turns the header into a bad request.
const initWait = 10 * time.Second

func (h *hostPeers) reaper() int {
	select {
	case <-h.known:
	case <-time.After(initWait):
	}
	return int(h.init.Load())
}

// TrustsHeader accepts identity headers only from the agent jail's init.
// bubblewrap reports the pid of its pid-namespace reaper, whose only child is
// doriath's init: init is a subreaper, so orphans never reparent to the
// reaper. The executable check rules out anything else that could appear
// there.
func (h *hostPeers) TrustsHeader(pid int) bool {
	reaper := h.reaper()
	if reaper == 0 || pid <= 0 || pid == reaper || parentPID(pid) != reaper {
		return false
	}
	if h.exe == "" {
		return false
	}
	running, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return false
	}
	own, err := os.Stat(h.exe)
	return err == nil && os.SameFile(running, own)
}

func (h *hostPeers) Exe(pid int) string {
	exe, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return ""
	}
	return exe
}

func parentPID(pid int) int {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0
	}
	fields := strings.Fields(s[i+1:])
	if len(fields) < 2 {
		return 0
	}
	ppid, _ := strconv.Atoi(fields[1])
	return ppid
}

// initRunning reports whether the reaper's child already runs doriath's
// binary. bubblewrap starts the jail's command only after it has built the
// jail, so from then on the namespaces are complete.
func (h *hostPeers) initRunning(reaper int) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || parentPID(pid) != reaper {
			continue
		}
		if h.TrustsHeader(pid) {
			return true
		}
	}
	return false
}
