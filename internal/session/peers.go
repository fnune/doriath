package session

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
)

// hostPeers identifies processes that connect to the session's sockets,
// using the host's /proc.
type hostPeers struct {
	init atomic.Int64
	// exe is girdle's own binary, which the jail's init runs.
	exe string
}

func (h *hostPeers) setInit(pid int) { h.init.Store(int64(pid)) }

// TrustsHeader accepts identity headers only from the agent jail's init.
// bubblewrap reports the pid of its pid-namespace reaper, whose only child is
// girdle's init: init is a subreaper, so orphans never reparent to the
// reaper. The executable check rules out anything else that could appear
// there.
func (h *hostPeers) TrustsHeader(pid int) bool {
	reaper := int(h.init.Load())
	if reaper == 0 || pid <= 0 || pid == reaper || parentPID(pid) != reaper {
		return false
	}
	if h.exe == "" {
		return false
	}
	// Inside the jail, init's binary has a different path than on the host,
	// so compare the files themselves.
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
	// The command name in field 2 can hold spaces and parentheses, so fields
	// are counted from the last closing parenthesis.
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
