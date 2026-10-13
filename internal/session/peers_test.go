package session

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestHeaderFromInitBeforeItsPidIsKnownIsTrusted(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	child := exec.Command(sleep, "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	peers := newHostPeers(sleep)
	go func() {
		time.Sleep(50 * time.Millisecond)
		peers.setInit(os.Getpid())
	}()
	if !peers.TrustsHeader(child.Process.Pid) {
		t.Fatal("a connection that arrived before the reaper's pid was recorded was not trusted")
	}
}
