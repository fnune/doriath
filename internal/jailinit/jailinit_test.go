package jailinit

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestParseForward(t *testing.T) {
	f, err := ParseForward("3128=/run/girdle/proxy.sock")
	if err != nil || f.Port != 3128 || f.Socket != "/run/girdle/proxy.sock" {
		t.Fatalf("got %+v, %v", f, err)
	}
	for _, bad := range []string{"3128", "x=/a", "0=/a", "70000=/a", "80=rel"} {
		if _, err := ParseForward(bad); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
	if f.String() != "3128=/run/girdle/proxy.sock" {
		t.Errorf("String = %q", f.String())
	}
}

func TestBridgeForwardsBothWays(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "up.sock")
	up, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				fmt.Fprintf(c, "echo %s", line)
			}()
		}
	}()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go Bridge(context.Background(), l, Forward{Socket: sock})

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprint(c, "hello\n")
	got, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || got != "echo hello\n" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestRunExitCodes(t *testing.T) {
	code, err := Run(nil, []string{"sh", "-c", "exit 7"})
	if err != nil || code != 7 {
		t.Fatalf("code %d, %v", code, err)
	}
	code, err = Run(nil, []string{"sh", "-c", "kill -TERM $$"})
	if err != nil || code != 128+15 {
		t.Fatalf("signalled: code %d, %v", code, err)
	}
	if code, _ := Run(nil, []string{"definitely-not-a-command-girdle"}); code != 127 {
		t.Fatalf("missing command: code %d", code)
	}
}

func TestFindPeerIdentifiesTheClientProcess(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	child := exec.Command(bash, "-c", fmt.Sprintf("exec 3<>/dev/tcp/127.0.0.1/%d; read -r _ <&3", port))
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := FindPeer("/proc", conn)
	if err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(bash)
	if peer.PID != child.Process.Pid || peer.Exe != real {
		t.Fatalf("peer = %+v, want pid %d exe %s", peer, child.Process.Pid, real)
	}
}

func TestPeerHeader(t *testing.T) {
	got := string(PeerHeader(Peer{PID: 7, Exe: "/nix/store/x-gh/bin/gh"}))
	if got != "GIRDLE-PEER {\"pid\":7,\"exe\":\"/nix/store/x-gh/bin/gh\"}\n" {
		t.Fatalf("got %q", got)
	}
}

func TestSoleOwnerRefusesDifferentPrograms(t *testing.T) {
	proc := t.TempDir()
	programs := t.TempDir()
	for _, name := range []string{"gh", "curl"} {
		if err := os.WriteFile(filepath.Join(programs, name), nil, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for pid, program := range map[string]string{"10": "gh", "11": "gh", "12": "curl"} {
		if err := os.MkdirAll(filepath.Join(proc, pid), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(programs, program), filepath.Join(proc, pid, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	peer, err := soleOwner(proc, []int{10, 11})
	if err != nil || peer.PID != 10 || filepath.Base(peer.Exe) != "gh" {
		t.Fatalf("one program, two processes: %+v, %v", peer, err)
	}
	if _, err := soleOwner(proc, []int{10, 12}); err == nil {
		t.Fatal("two programs sharing a socket must not get an identity")
	}
}
