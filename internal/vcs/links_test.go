package vcs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func foreignFolder(t *testing.T, files ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("yours"), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err != nil {
		t.Errorf("%s was removed or moved: %v", path, err)
	}
}

func TestFinishDoesNotListAWorktreesLinkAsAgentWorktrees(t *testing.T) {
	r := repo(t)
	yours := foreignFolder(t, "thesis.docx", "notes.txt")
	f := start(t, &Record{Session: "s1", Writable: []string{r}}, r)
	worktrees := filepath.Join(r, ".git", "worktrees")
	if err := os.RemoveAll(worktrees); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(yours, worktrees); err != nil {
		t.Fatal(err)
	}
	out := f.finish()
	mustExist(t, filepath.Join(yours, "thesis.docx"))
	mustExist(t, filepath.Join(yours, "notes.txt"))
	if !strings.Contains(out, "made "+worktrees+" a link") {
		t.Errorf("Finish did not report the link:\n%s", out)
	}
	if _, err := os.Lstat(worktrees); err == nil {
		t.Errorf("the link is still at %s", worktrees)
	}
}

func TestFinishDoesNotWalkAnLFSLink(t *testing.T) {
	r := repo(t)
	yours := foreignFolder(t, "objects/ab/cdef0123456789")
	rec := &Record{Session: "s2", Writable: []string{r}, Started: time.Now().Add(-time.Hour)}
	f := start(t, rec, r)
	rec.Started = time.Now().Add(-time.Minute)
	if err := os.Symlink(yours, filepath.Join(r, ".git", "lfs")); err != nil {
		t.Fatal(err)
	}
	f.finish()
	mustExist(t, filepath.Join(yours, "objects", "ab", "cdef0123456789"))
}

func TestFinishDoesNotMoveStoresBehindAModulesLink(t *testing.T) {
	r := repo(t)
	parent := t.TempDir()
	other := filepath.Join(parent, "other")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, other, "init", "-q", "-b", "main")
	rec := &Record{Session: "s3", Writable: []string{r}, Started: time.Now().Add(-time.Minute)}
	f := start(t, rec, r)
	if err := os.Symlink(parent, filepath.Join(r, ".git", "modules")); err != nil {
		t.Fatal(err)
	}
	git(t, other, "commit", "-q", "--allow-empty", "-m", "yours")
	f.finish()
	mustExist(t, filepath.Join(other, ".git", "HEAD"))
}

func TestPrepareLeavesLinksAtStoreFolders(t *testing.T) {
	r := repo(t)
	disk := foreignFolder(t, "objects/ab/cd")
	if err := os.RemoveAll(filepath.Join(r, ".git", "lfs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(disk, filepath.Join(r, ".git", "lfs")); err != nil {
		t.Fatal(err)
	}
	if err := Prepare(context.Background(), Tools{Git: "git"}, r); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(filepath.Join(r, ".git", "lfs")); err != nil || target != disk {
		t.Errorf("the link of the person is gone: %q, %v", target, err)
	}
}

func TestFinishKeepsALinkThatWasThereAtTheStart(t *testing.T) {
	r := repo(t)
	disk := foreignFolder(t, "objects/ab/cd")
	if err := os.Symlink(disk, filepath.Join(r, ".git", "lfs")); err != nil {
		t.Fatal(err)
	}
	f := start(t, &Record{Session: "s1", Started: time.Now()}, r)
	out := f.finish()
	if target, err := os.Readlink(filepath.Join(r, ".git", "lfs")); err != nil || target != disk {
		t.Errorf("Finish removed the link of the person: %q, %v\n%s", target, err, out)
	}
	mustExist(t, filepath.Join(disk, "objects", "ab", "cd"))
}

func TestFinishPutsBackALinkTheAgentPointedElsewhere(t *testing.T) {
	r := repo(t)
	disk := foreignFolder(t, "objects/ab/cd")
	other := foreignFolder(t, "x")
	lfs := filepath.Join(r, ".git", "lfs")
	if err := os.Symlink(disk, lfs); err != nil {
		t.Fatal(err)
	}
	f := start(t, &Record{Session: "s1", Started: time.Now()}, r)
	if err := os.Remove(lfs); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, lfs); err != nil {
		t.Fatal(err)
	}
	out := f.finish()
	if target, err := os.Readlink(lfs); err != nil || target != disk {
		t.Errorf("link = %q, %v, want %q", target, err, disk)
	}
	if !strings.Contains(out, "put it back") {
		t.Errorf("Finish did not report it:\n%s", out)
	}
	mustExist(t, filepath.Join(other, "x"))
}

func TestFinishDoesNotCheckAStoreBehindAnOuterModulesLink(t *testing.T) {
	r := repo(t)
	modules := filepath.Join(r, ".git", "modules")
	outer, inner := filepath.Join(modules, "a"), filepath.Join(modules, "a", "modules", "b")
	for _, dir := range []string{outer, inner} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		git(t, dir, "init", "-q", "--bare", "-b", "main")
	}
	rec := &Record{Session: "s1", Started: time.Now()}
	f := start(t, rec, r)
	if len(rec.Repos) != 3 {
		t.Fatalf("the test needs the nested store recorded: %d repos", len(rec.Repos))
	}
	elsewhere := filepath.Join(t.TempDir(), "a")
	if err := os.Rename(outer, elsewhere); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, outer); err != nil {
		t.Fatal(err)
	}
	out := f.finish()
	if !strings.Contains(out, "did not check") {
		t.Errorf("Finish checked a store behind a link:\n%s", out)
	}
}

func TestModuleStoresStopsAtADepth(t *testing.T) {
	root := t.TempDir()
	deep := root
	for range 30 {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(filepath.Join(deep, "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ModuleStores(root, osDirs{}); len(got) != 0 {
		t.Errorf("found a store %d levels down: %v", 30, got)
	}
}
