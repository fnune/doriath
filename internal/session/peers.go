package session

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fnune/doriath/internal/jailinit"
	"github.com/fnune/doriath/internal/proxy"
)

type hostPeers struct {
	init  atomic.Int64
	known chan struct{}
	once  sync.Once
	exe   string
	pins  pins
	proc  string
}

func newHostPeers(exe string) *hostPeers {
	return &hostPeers{exe: exe, known: make(chan struct{}), proc: "/proc"}
}

func (h *hostPeers) setInit(pid int) {
	h.init.Store(int64(pid))
	h.once.Do(func() { close(h.known) })
}

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

func (h *hostPeers) Identify(pid int) proxy.Identity {
	peer, err := jailinit.Describe("/proc", pid)
	if err != nil {
		return proxy.Identity{PID: pid}
	}
	return proxy.Identity{PID: pid, Exe: peer.Exe, File: peer.File, Code: peer.Code}
}

func (h *hostPeers) Vouch(id proxy.Identity) proxy.Identity {
	id.Untrusted = h.pins.untrusted(id)
	return id
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

// hostPID finds the process that the jail's pid names. The jail reports pids
// of its own namespace, which mean other processes outside.
func hostPID(procRoot string, reaper, jailPID int) (int, error) {
	space, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(reaper), "ns", "pid"))
	if err != nil {
		return 0, fmt.Errorf("find the pid namespace of the jail: %w", err)
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join(procRoot, e.Name())
		if got, err := os.Readlink(filepath.Join(dir, "ns", "pid")); err != nil || got != space {
			continue
		}
		status, err := os.ReadFile(filepath.Join(dir, "status"))
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(status), "\n") {
			if fields, ok := strings.CutPrefix(line, "NSpid:"); ok {
				ids := strings.Fields(fields)
				if len(ids) > 1 && ids[len(ids)-1] == strconv.Itoa(jailPID) {
					return pid, nil
				}
			}
		}
	}
	return 0, fmt.Errorf("no process of the jail has pid %d", jailPID)
}
