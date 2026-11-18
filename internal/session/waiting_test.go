package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/proxy"
)

func fakeProc(t *testing.T) (proc, stderr string) {
	t.Helper()
	jailNS := "pid:[100]"
	proc = t.TempDir()
	stderr = filepath.Join(t.TempDir(), "stderr")
	if err := os.WriteFile(stderr, []byte("earlier output\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	process := func(hostPID, nsPIDs, ns string) string {
		dir := filepath.Join(proc, hostPID)
		for _, d := range []string{"ns", "fd"} {
			if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(ns, filepath.Join(dir, "ns", "pid")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte("Name:\tx\nNSpid:\t"+nsPIDs+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	process("4000", "4000\t1", jailNS)
	dir := process("4100", "4100\t37", jailNS)
	if err := os.Symlink(stderr, filepath.Join(dir, "fd", "2")); err != nil {
		t.Fatal(err)
	}
	process("4200", "4200\t37", "pid:[999]")
	return proc, stderr
}

func TestHintReachesTheJailProcessByItsPidInTheJail(t *testing.T) {
	proc, stderr := fakeProc(t)
	h := newHostPeers("")
	h.proc = proc
	h.setInit(4000)
	h.writeToStderr(37, "doriath: hello\n")
	got, err := os.ReadFile(stderr)
	if err != nil || string(got) != "earlier output\ndoriath: hello\n" {
		t.Fatalf("stderr = %q, %v", got, err)
	}
}

func TestHintSkipsAProcessOutsideTheJail(t *testing.T) {
	proc, stderr := fakeProc(t)
	if err := os.Remove(filepath.Join(proc, "4100", "fd", "2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(stderr, filepath.Join(proc, "4200", "fd", "2")); err != nil {
		t.Fatal(err)
	}
	h := newHostPeers("")
	h.proc = proc
	h.setInit(4000)
	h.writeToStderr(37, "doriath: hello\n")
	if got, _ := os.ReadFile(stderr); string(got) != "earlier output\n" {
		t.Fatalf("wrote to a process in another pid namespace: %q", got)
	}
}

func TestHintSkipsTheTerminalOfTheSession(t *testing.T) {
	proc, _ := fakeProc(t)
	if err := os.MkdirAll(filepath.Join(proc, "4000", "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(os.DevNull, filepath.Join(proc, "4000", "fd", "0")); err != nil {
		t.Fatal(err)
	}
	fd2 := filepath.Join(proc, "4100", "fd", "2")
	if err := os.Remove(fd2); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(os.DevNull, fd2); err != nil {
		t.Fatal(err)
	}
	h := newHostPeers("")
	h.proc = proc
	h.setInit(4000)
	if !h.isSessionTerminal(fd2) {
		t.Fatal("a character device that the session's own streams use must not get the hint")
	}
	other := filepath.Join(proc, "4000", "fd", "0")
	if err := os.Remove(other); err != nil {
		t.Fatal(err)
	}
	if h.isSessionTerminal(fd2) {
		t.Fatal("a device that the session does not use is not its terminal")
	}
}

func TestHintNamesTheRequestAndHowToAnswerIt(t *testing.T) {
	ts := newTestSession(t, &answering{seen: make(chan approval.Request, 1)})
	proc, stderr := fakeProc(t)
	ts.peers.proc = proc
	ts.peers.setInit(4000)
	summary := "Create a GitHub release\x1b[2J"
	go func() {
		_, _ = ts.manager.Submit(t.Context(), approval.Request{Session: "s1", Kind: approval.KindHTTP, Summary: summary}, 10*time.Minute)
	}()
	var pending []approval.Request
	for len(pending) == 0 {
		pending = ts.manager.Pending()
	}
	ts.Waiting(proxy.Identity{PID: 37}, summary)
	got, _ := os.ReadFile(stderr)
	for _, want := range []string{"doriath: waiting for approval of Create a GitHub release\\u001b[2J.", "`doriath approvals allow " + pending[0].ID + "`", "Do not retry", "10m0s"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("hint lacks %q:\n%s", want, got)
		}
	}
}

func TestHintNamesAHeldHost(t *testing.T) {
	ts := newTestSession(t, &answering{})
	proc, stderr := fakeProc(t)
	ts.peers.proc = proc
	ts.peers.setInit(4000)
	summary := ts.hostSummary("drafted.example")
	go func() {
		_, _ = ts.manager.Submit(t.Context(), approval.Request{Session: "s1", Kind: approval.KindHost, Summary: summary}, 10*time.Minute)
	}()
	for len(ts.manager.Pending()) == 0 {
	}
	ts.hintPending(proxy.Identity{PID: 37}, approval.KindHost, summary)
	got, _ := os.ReadFile(stderr)
	if !strings.Contains(string(got), "waiting for approval of Allow drafted.example for profile p?") {
		t.Errorf("hint = %q", got)
	}
}
