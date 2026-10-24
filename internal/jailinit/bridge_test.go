package jailinit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// upstream is a unix socket server that hands each connection's first two
// lines to the test.
func upstream(t *testing.T) (sock string, lines <-chan [2]string) {
	t.Helper()
	sock = filepath.Join(t.TempDir(), "up.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	ch := make(chan [2]string, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()

		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(c)
		first, _ := r.ReadString('\n')
		second, _ := r.ReadString('\n')
		ch <- [2]string{first, second}
	}()
	return sock, ch
}

func bridge(t *testing.T, f Forward) net.Addr {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go Bridge(t.Context(), l, f)
	return l.Addr()
}

func TestBridgeNamesTheClientProgramToTheSocket(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	sock, lines := upstream(t)
	addr := bridge(t, Forward{Socket: sock, Identify: true}).(*net.TCPAddr)
	child := exec.Command(bash, "-c", fmt.Sprintf("exec 3<>/dev/tcp/127.0.0.1/%d; echo hello >&3; read -r _ <&3", addr.Port))
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })

	got := <-lines
	real, _ := filepath.EvalSymlinks(bash)
	info, err := os.Stat(real)
	if err != nil {
		t.Fatal(err)
	}
	var peer Peer
	if err := json.Unmarshal([]byte(strings.TrimPrefix(got[0], "DORIATH-PEER ")), &peer); err != nil {
		t.Fatalf("header %q: %v", got[0], err)
	}
	if peer.PID != child.Process.Pid || peer.Exe != real || peer.File != FileIDOf(info) || !slices.ContainsFunc(peer.Code, func(f MappedFile) bool { return f.Path == real && f.File == peer.File }) {
		t.Errorf("header = %q, want bash %s and the code it maps", got[0], real)
	}
	if got[1] != "hello\n" {
		t.Errorf("the client's bytes must follow the header: %q", got[1])
	}
}

func TestBridgeClosesTheConnectionWhenTheSocketIsDown(t *testing.T) {
	addr := bridge(t, Forward{Socket: filepath.Join(t.TempDir(), "missing.sock")})
	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if n, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read = %d, %v, want EOF", n, err)
	}
}

func TestFindPeerRefusesWhatItCannotName(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := FindPeer("/proc", a); err == nil {
		t.Error("a connection that is not TCP has no peer")
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if peer, err := FindPeer("/proc", server); err == nil {
		t.Errorf("init must never name itself: %+v", peer)
	}
}

// takenPort is a loopback port something else listens on until the test
// ends.
func takenPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l.Addr().(*net.TCPAddr).Port
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func TestListenClosesWhatItOpenedWhenAPortIsTaken(t *testing.T) {
	free := freePort(t)
	if _, err := Listen([]Forward{{Port: free, Socket: "/a"}, {Port: takenPort(t), Socket: "/b"}}); err == nil {
		t.Fatal("a taken port must be an error")
	}
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", free))
	if err != nil {
		t.Fatalf("the listener opened before the failure stays open: %v", err)
	}
	_ = l.Close()
}

func TestRunStartsNothingWhenAPortIsTaken(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "started")
	code, err := Run([]Forward{{Port: takenPort(t), Socket: "/a"}}, []string{"touch", marker})
	if err == nil || code != 1 {
		t.Fatalf("code %d, %v", code, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Error("the agent must not start without its forwards")
	}
}

func TestRunExitCodesForCommandsThatCannotRun(t *testing.T) {
	garbage := filepath.Join(t.TempDir(), "garbage")
	if err := os.WriteFile(garbage, []byte{0x7f, 'E', 'L', 'F', 0}, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		argv []string
		code int
	}{
		{nil, 2},
		{[]string{"definitely-not-a-command-doriath"}, 127},
		{[]string{garbage}, 126},
	} {
		code, err := Run(nil, c.argv)
		if err == nil || code != c.code {
			t.Errorf("%q: code %d, %v, want %d", c.argv, code, err, c.code)
		}
		if err != nil && !strings.HasPrefix(err.Error(), "init: ") {
			t.Errorf("%q: the error must say init failed: %v", c.argv, err)
		}
	}
}
