package vcs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// watch runs Watch until stop, which returns what it reported. The test
// stops it on cleanup too.
func watch(t *testing.T, rec *Record) (stop func() string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var out strings.Builder
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := Watch(ctx, rec, &out); err != nil {
			t.Error(err)
		}
	}()
	stop = func() string {
		cancel()
		<-done
		return out.String()
	}
	t.Cleanup(func() { stop() })
	return stop
}

func TestWatchRepairsAgentWorktreesDuringTheSession(t *testing.T) {
	r := repo(t)
	trees := filepath.Join(filepath.Dir(r), "trees")
	if err := os.MkdirAll(filepath.Join(r, ".git", "worktrees"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec := &Record{Session: "s1", Writable: []string{trees}}
	start(t, rec, r)
	stop := watch(t, rec)

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
	eventually(t, "config.worktree is emptied", func() bool {
		data, err := os.ReadFile(filepath.Join(admin, "config.worktree"))
		return err == nil && len(data) == 0
	})

	git(t, r, "worktree", "remove", checkout)
	out := stop()
	if _, err := os.Stat(admin); !os.IsNotExist(err) {
		t.Errorf("git worktree remove must still work, admin directory: %v\n%s", err, out)
	}
}

// A session that starts while this one runs holds an empty config.worktree
// in every worktree, including those this session's agent added.
func TestWatchLeavesTheEmptyConfigOfAnotherSession(t *testing.T) {
	r := repo(t)
	trees := filepath.Join(filepath.Dir(r), "trees")
	if err := os.MkdirAll(filepath.Join(r, ".git", "worktrees"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec := &Record{Session: "s1", Writable: []string{trees}}
	start(t, rec, r)
	stop := watch(t, rec)

	checkout := filepath.Join(trees, "agent")
	admin := filepath.Join(r, ".git", "worktrees", "agent")
	git(t, r, "worktree", "add", "-q", checkout, "-b", "agent")
	if err := os.WriteFile(filepath.Join(admin, "config.worktree"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(admin, "commondir"), []byte("/tmp/evil.git\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	eventually(t, "commondir points back", func() bool {
		data, _ := os.ReadFile(filepath.Join(admin, "commondir"))
		return string(data) == "../..\n"
	})
	out := stop()
	if _, err := os.Stat(filepath.Join(admin, "config.worktree")); err != nil {
		t.Errorf("the empty config is gone: %v\n%s", err, out)
	}
}

func TestWatchRepairsWorktreesAddedBeforeItStarted(t *testing.T) {
	r := repo(t)
	trees := filepath.Join(filepath.Dir(r), "trees")
	rec := &Record{Session: "s1", Writable: []string{trees}}
	start(t, rec, r)
	checkout := filepath.Join(trees, "early")
	git(t, r, "worktree", "add", "-q", checkout, "-b", "early")
	if err := os.WriteFile(filepath.Join(checkout, ".git"), []byte("gitdir: /tmp/evil.git\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	stop := watch(t, rec)
	eventually(t, "the .git file points back", func() bool {
		return pointsTo(checkout, filepath.Join(r, ".git", "worktrees", "early"))
	})
	if out := stop(); !strings.Contains(out, "pointed worktree "+checkout+" back") {
		t.Errorf("output: %q", out)
	}
}

// eventually polls, since inotify gives the test no event to wait on.
func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("%s: not within 2s", what)
}
