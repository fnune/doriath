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

func TestAKeptLinkBehindAFolderThatTheJailReplacedWithASymlinkLeavesTheHostFileAlone(t *testing.T) {
	mount := t.TempDir()
	victims := t.TempDir()
	if err := os.WriteFile(filepath.Join(victims, "config.toml"), []byte("host file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(mount, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "config.toml")
	link := filepath.Join(mount, "sub", "config.toml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	r := &restoredLinks{found: map[string]string{}}
	k := newLinkKeeper(r.report)
	k.rootOf = func(string) string { return mount }
	defer k.Close()
	if err := k.Keep(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(mount, "sub"), filepath.Join(mount, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victims, filepath.Join(mount, "sub")); err != nil {
		t.Fatal(err)
	}
	k.Check()
	data, err := os.ReadFile(filepath.Join(victims, "config.toml"))
	if err != nil || string(data) != "host file" {
		t.Fatalf("host file = %q, %v", data, err)
	}
}

func TestAKeptLinkOutsideEveryWritableFolderIsReportedAndNotRestoredByPlainPath(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "config.toml")
	if err := os.Symlink(filepath.Join(t.TempDir(), "config.toml"), link); err != nil {
		t.Fatal(err)
	}
	r := &restoredLinks{found: map[string]string{}}
	k := newLinkKeeper(r.report)
	k.rootOf = func(string) string { return "" }
	defer k.Close()
	if err := k.Keep(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	k.Check()
	if _, ok := r.found[link]; !ok {
		t.Errorf("no report for %s: %v", link, r.found)
	}
	if exists(link) {
		t.Error("the link came back through a root that follows symlinks")
	}
}
