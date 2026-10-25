package jailinit

import (
	"os"
	"os/exec"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

const takeTerminalChild = "JAILINIT_TAKE_TERMINAL_CHILD"

func TestInitTakesAPtyThatIsNoOnesTerminal(t *testing.T) {
	if os.Getenv(takeTerminalChild) != "" {
		if err := takeTerminal(0); err != nil {
			t.Fatal(err)
		}
		sid, err := unix.IoctlGetInt(0, unix.TIOCGSID)
		if err != nil || sid != os.Getpid() {
			t.Fatalf("session of the pty %d, %v; want %d", sid, err, os.Getpid())
		}
		return
	}
	master, tty := openPty(t)
	defer master.Close()
	defer tty.Close()
	runChild(t, tty)
}

func TestInitLeavesInputThatIsNoTerminal(t *testing.T) {
	if os.Getenv(takeTerminalChild) != "" {
		before, _ := unix.Getsid(0)
		if err := takeTerminal(0); err != nil {
			t.Fatal(err)
		}
		if after, _ := unix.Getsid(0); after != before {
			t.Fatalf("session changed from %d to %d", before, after)
		}
		return
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	runChild(t, r)
}

func runChild(t *testing.T, stdin *os.File) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), takeTerminalChild+"=1")
	cmd.Stdin = stdin
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}

func openPty(t *testing.T) (master, tty *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	fd := int(master.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetUint32(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	tty, err = os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(n), 10), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	return master, tty
}
