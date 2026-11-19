package main

import (
	"math"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func isInternalCommand(args []string) bool {
	return len(args) > 0 && strings.HasPrefix(args[0], "__")
}

func closeInheritedOnExec() {
	if err := unix.CloseRange(3, math.MaxUint32, unix.CLOSE_RANGE_CLOEXEC); err == nil {
		return
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return
	}
	for _, e := range entries {
		if fd, err := strconv.Atoi(e.Name()); err == nil && fd > 2 {
			_, _ = unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC)
		}
	}
}
