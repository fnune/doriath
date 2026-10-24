package session

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type restoredLinks struct {
	mu    sync.Mutex
	found map[string]string
}

func (r *restoredLinks) report(path, found string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.found[path] = found
}

func (r *restoredLinks) get(path string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.found[path]
}

func linkIn(t *testing.T) (dir, link, target string) {
	t.Helper()
	dir = t.TempDir()
	target = filepath.Join(t.TempDir(), "config.toml")
	link = filepath.Join(dir, "config.toml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	return dir, link, target
}

func TestAKeptLinkThatTheJailReplacesIsPutBackAtOnce(t *testing.T) {
	dir, link, target := linkIn(t)
	r := &restoredLinks{found: map[string]string{}}
	k := newLinkKeeper(r.report)
	defer k.Close()
	if err := k.Keep(link); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(dir, "planted")
	if err := os.WriteFile(planted, []byte("[aliases]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(planted, link); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for r.get(link) == "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got, err := os.Readlink(link); err != nil || got != target {
		t.Fatalf("link = %q, %v, want %q", got, err, target)
	}
	if found := r.get(link); found != "a file or folder" {
		t.Errorf("reported %q", found)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("entries = %v", entries)
	}
}

func TestTheLastCheckPutsBackALinkChangedAfterTheWatchStopped(t *testing.T) {
	_, link, target := linkIn(t)
	r := &restoredLinks{found: map[string]string{}}
	k := newLinkKeeper(r.report)
	if err := k.Keep(link); err != nil {
		t.Fatal(err)
	}
	k.Close()
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/elsewhere", link); err != nil {
		t.Fatal(err)
	}
	k.Check()
	if got, _ := os.Readlink(link); got != target || !strings.Contains(r.get(link), "/elsewhere") {
		t.Errorf("link = %q, reported %q", got, r.get(link))
	}
}

func TestAnUnchangedLinkIsNotReported(t *testing.T) {
	_, link, _ := linkIn(t)
	r := &restoredLinks{found: map[string]string{}}
	k := newLinkKeeper(r.report)
	defer k.Close()
	if err := k.Keep(link); err != nil {
		t.Fatal(err)
	}
	k.Check()
	if len(r.found) != 0 {
		t.Errorf("reported %v", r.found)
	}
}
