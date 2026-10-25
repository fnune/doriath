package termbar

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func TestTheProgramStaysInYourProcessGroupForTerminalsThatLookForIt(t *testing.T) {
	master, tty, err := openPty()
	if err != nil {
		t.Skip(err)
	}
	defer master.Close()
	defer tty.Close()
	if err := unix.IoctlSetWinsize(int(tty.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 80}); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = master.Read(make([]byte, 1<<16)) }()
	b, err := Open(tty, tty)
	if err != nil || b == nil {
		t.Fatalf("open: %v, %v", b, err)
	}
	cmd := exec.Command("sleep", "10")
	if err := b.Start(cmd); err != nil {
		t.Fatal(err)
	}
	pgid, err := unix.Getpgid(cmd.Process.Pid)
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	_ = b.Close()
	if err != nil || pgid != unix.Getpgrp() {
		t.Fatalf("process group %d, %v; want %d", pgid, err, unix.Getpgrp())
	}
}
