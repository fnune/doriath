package vcs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWatchRepairsAgentWorktreesDuringTheSession(t *testing.T) {
	r := repo(t)
	trees := filepath.Join(filepath.Dir(r), "trees")
	if err := os.MkdirAll(filepath.Join(r, ".git", "worktrees"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec := &Record{Session: "s1", Writable: []string{trees}}
	start(t, rec, r)
	ctx, cancel := context.WithCancel(context.Background())
	var out strings.Builder
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := Watch(ctx, rec, &out); err != nil {
			t.Error(err)
		}
	}()
	stop := func() {
		cancel()
		<-done
	}
	defer stop()

	checkout := filepath.Join(trees, "agent")
	admin := filepath.Join(r, ".git", "worktrees", "agent")
	git(t, r, "worktree", "add", "-q", checkout, "-b", "agent")
	if err := os.WriteFile(filepath.Join(checkout, ".git"), []byte("gitdir: /tmp/evil.git\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the .git file points back", func() bool { return pointsTo(checkout, admin) })
	if err := os.WriteFile(filepath.Join(admin, "commondir"), []byte("/tmp/evil.git\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	eventually(t, "commondir points back", func() bool {
		data, _ := os.ReadFile(filepath.Join(admin, "commondir"))
		return string(data) == "../..\n"
	})
	if err := os.WriteFile(filepath.Join(admin, "config.worktree"), []byte("[core]\nfsmonitor = /tmp/x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	eventually(t, "config.worktree is removed", func() bool {
		_, err := os.Stat(filepath.Join(admin, "config.worktree"))
		return os.IsNotExist(err)
	})

	git(t, r, "worktree", "remove", checkout)
	stop()
	if _, err := os.Stat(admin); !os.IsNotExist(err) {
		t.Errorf("git worktree remove must still work, admin directory: %v\n%s", err, out.String())
	}
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("%s: not within 2s", what)
}
