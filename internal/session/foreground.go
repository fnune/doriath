package session

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

func firstTerminal(streams ...any) *os.File {
	for _, stream := range streams {
		if f, ok := stream.(*os.File); ok && f != nil {
			if _, err := unix.IoctlGetInt(int(f.Fd()), unix.TIOCGSID); err == nil {
				return f
			}
		}
	}
	return nil
}

func takeBackForeground(tty *os.File) {
	signal.Ignore(syscall.SIGTTOU)
	defer signal.Reset(syscall.SIGTTOU)
	group, err := unix.IoctlGetInt(int(tty.Fd()), unix.TIOCGPGRP)
	if err != nil || group == syscall.Getpgrp() {
		return
	}
	_ = unix.IoctlSetPointerInt(int(tty.Fd()), unix.TIOCSPGRP, syscall.Getpgrp())
}
