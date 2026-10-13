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
}

func (h *hostPeers) setInit(pid int) { h.init.Store(int64(pid)) }

// TrustsHeader accepts identity headers only from the agent jail's init.
// bubblewrap reports the pid of its first child, which is either init itself
// or bubblewrap's pid-namespace reaper, whose child init is.
func (h *hostPeers) TrustsHeader(pid int) bool {
	init := int(h.init.Load())
	if init == 0 || pid <= 0 {
		return false
	}
	return pid == init || parentPID(pid) == init
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
