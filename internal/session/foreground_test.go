package session

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const foregroundChild = "SESSION_FOREGROUND_CHILD"

func TestDoriathTakesTheTerminalBackWhenTheAgentGroupEnds(t *testing.T) {
	if os.Getenv(foregroundChild) != "" {
		agent := exec.Command("true")
		agent.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Foreground: true, Ctty: 0}
		if err := agent.Run(); err != nil {
			t.Fatal(err)
		}
		if group, _ := unix.IoctlGetInt(0, unix.TIOCGPGRP); group == syscall.Getpgrp() {
			t.Fatal("setup: the agent group did not take the terminal")
		}
		piped, _, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if got := firstTerminal(piped, os.Stdout, os.Stderr); got != os.Stdout {
			t.Fatalf("with a piped stdin the terminal is %v, want stdout", got)
		}
		takeBackForeground(firstTerminal(piped, os.Stdout, os.Stderr))
		if group, _ := unix.IoctlGetInt(0, unix.TIOCGPGRP); group != syscall.Getpgrp() {
			t.Fatalf("foreground group %d, want %d", group, syscall.Getpgrp())
		}
		return
	}
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	defer master.Close()
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetUint32(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	tty, err := os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(n), 10), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer tty.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), foregroundChild+"=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
}
