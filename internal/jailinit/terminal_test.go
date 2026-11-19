package jailinit

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
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

const runInitChild = "JAILINIT_RUN_CHILD"

func TestAgentRunsInItsOwnForegroundProcessGroup(t *testing.T) {
	if os.Getenv(runInitChild) != "" {
		code, err := Run(nil, []string{"sh", "-c", `awk '{print "pgrp=" $5 " foreground=" $8}' /proc/self/stat; echo "init=$PPID"`})
		if err != nil || code != 0 {
			t.Fatalf("run: %d, %v", code, err)
		}
		return
	}
	master, tty := openPty(t)
	defer master.Close()
	defer tty.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), runInitChild+"=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _ := master.Read(buf)
	var pgrp, foreground, init int
	if _, err := fmt.Sscanf(strings.ReplaceAll(string(buf[:n]), "\r", ""), "pgrp=%d foreground=%d\ninit=%d", &pgrp, &foreground, &init); err != nil {
		t.Fatalf("output %q: %v", buf[:n], err)
	}
	if pgrp != foreground || pgrp == init || pgrp == cmd.Process.Pid {
		t.Fatalf("agent group %d, terminal foreground %d, init %d, session %d: want the agent in a group of its own that owns the terminal", pgrp, foreground, init, cmd.Process.Pid)
	}
}

func TestAgentWithoutATerminalRunsInItsOwnProcessGroup(t *testing.T) {
	if os.Getenv(runInitChild) != "" {
		_, _ = Run(nil, []string{"sh", "-c", `awk '{print $5}' /proc/self/stat; echo $PPID`})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), runInitChild+"=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		t.Fatalf("output %q", out)
	}
	if fields[0] == fields[1] || fields[0] == strconv.Itoa(syscall.Getpgrp()) {
		t.Fatalf("output %q: the agent shares a process group", out)
	}
}

func TestKillZeroFromTheAgentLeavesInit(t *testing.T) {
	if os.Getenv(runInitChild) != "" {
		code, err := Run(nil, []string{"sh", "-c", "kill -TERM 0; sleep 1"})
		fmt.Printf("init survived, agent code %d, %v\n", code, err)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), runInitChild+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.Output()
	if err != nil || !strings.Contains(string(out), "init survived, agent code 143") {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestControlCReachesTheAgentAndNotInit(t *testing.T) {
	if os.Getenv(runInitChild) != "" {
		code, err := Run(nil, []string{"/usr/bin/python3", "-c", `
import signal, sys, time
signal.signal(signal.SIGINT, lambda *a: (print("agent got interrupt", flush=True), sys.exit(7)))
print("ready", flush=True)
time.sleep(10)
`})
		fmt.Printf("init survived, agent code %d, %v\n", code, err)
		return
	}
	if _, err := os.Stat("/usr/bin/python3"); err != nil {
		t.Skip("no python3")
	}
	master, tty := openPty(t)
	defer master.Close()
	defer tty.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), runInitChild+"=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var seen strings.Builder
	buf := make([]byte, 4096)
	for !strings.Contains(seen.String(), "ready") {
		n, err := master.Read(buf)
		if err != nil {
			t.Fatalf("output %q: %v", seen.String(), err)
		}
		seen.Write(buf[:n])
	}
	if _, err := master.Write([]byte{3}); err != nil {
		t.Fatal(err)
	}
	for !strings.Contains(seen.String(), "agent code 7") {
		n, err := master.Read(buf)
		if err != nil {
			t.Fatalf("output %q: %v", seen.String(), err)
		}
		seen.Write(buf[:n])
	}
	_ = cmd.Wait()
}
