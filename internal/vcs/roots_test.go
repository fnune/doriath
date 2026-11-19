package vcs

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/fnune/doriath/internal/fswatch"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestTheRootGuardRemovesEveryCommondirInAStore(t *testing.T) {
	yours, agents := filepath.Join(t.TempDir(), ".git"), filepath.Join(t.TempDir(), ".git")
	for _, d := range []string{yours, agents} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(yours, Commondir), placeholderCommondir, 0o644); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	g, err := NewRootGuard(&out)
	if err != nil {
		t.Fatal(err)
	}
	g.Add(yours, agents)
	if _, err := os.Lstat(filepath.Join(yours, Commondir)); !os.IsNotExist(err) {
		t.Error("doriath's old placeholder stays, and nix cannot read the repository")
	}
	if out.String() != "" {
		t.Errorf("removing doriath's own placeholder is not news: %q", out.String())
	}
	planted := filepath.Join(agents, Commondir)
	if err := os.WriteFile(planted, []byte("/tmp/elsewhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if _, err := os.Lstat(planted); os.IsNotExist(err) {
			break
		}
	}
	if _, err := os.Lstat(planted); !os.IsNotExist(err) {
		t.Error("git on your machine follows the agent's commondir while the session runs")
	}
	g.Close()
	g.Close()
	if !strings.Contains(out.String(), "removed "+planted) {
		t.Errorf("report: %q", out.String())
	}
}

func TestARootGuardRemovesACommondirAfterAnOverflow(t *testing.T) {
	root := t.TempDir()
	var out strings.Builder
	g := &RootGuard{w: &lockedWriter{w: &out}, all: []string{root}}
	p := filepath.Join(root, Commondir)
	if err := os.WriteFile(p, []byte("/tmp/elsewhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g.handle(fswatch.Event{Mask: unix.IN_Q_OVERFLOW})
	if _, err := os.Lstat(p); err == nil {
		t.Error("the commondir stays after an overflow")
	}
}
