package vcs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareCreatesWhatGitWouldOnFirstUse(t *testing.T) {
	r := repo(t)
	gitDir := filepath.Join(r, ".git")
	for _, name := range []string{"worktrees", "logs", "refs"} {
		if err := os.RemoveAll(filepath.Join(gitDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	nested := filepath.Join(gitDir, "modules", "lib", "modules", "inner")
	if err := os.MkdirAll(filepath.Join(nested, "objects"), 0o755); err != nil {
		t.Fatal(err)
	}
	theirs := filepath.Join(gitDir, "modules", "lib", "objects", "info", "alternates")
	if err := os.MkdirAll(filepath.Dir(theirs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(theirs, []byte("/srv/shared/objects\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	notes, err := Prepare(context.Background(), Tools{Git: "git"}, r)
	if err != nil || notes != nil {
		t.Fatalf("Prepare = %v, %v", notes, err)
	}
	for _, name := range []string{"worktrees", "logs", "refs"} {
		if !isDir(filepath.Join(gitDir, name)) {
			t.Errorf("%s is missing", name)
		}
	}
	for _, store := range []string{gitDir, nested} {
		if data, err := os.ReadFile(filepath.Join(store, "objects", "info", "alternates")); err != nil || len(data) != 0 {
			t.Errorf("%s needs an empty alternates for the jail to bind: %q, %v", store, data, err)
		}
	}
	if data, _ := os.ReadFile(theirs); string(data) != "/srv/shared/objects\n" {
		t.Errorf("alternates you set up must stay: %q", data)
	}
	if _, err := os.Stat(filepath.Join(r, ".jj")); !os.IsNotExist(err) {
		t.Error("a git repository must not get jj files")
	}
}

func TestPrepareLeavesTheGitConfigOfAColocatedRepositoryAlone(t *testing.T) {
	r := jjRepo(t, true)
	before, err := os.ReadFile(filepath.Join(r, ".git", "config"))
	if err != nil {
		t.Fatal(err)
	}
	notes, err := Prepare(context.Background(), Tools{Git: "git", JJ: "jj"}, r)
	if err != nil || len(notes) != 0 {
		t.Fatalf("Prepare = %q, %v", notes, err)
	}
	if after, _ := os.ReadFile(filepath.Join(r, ".git", "config")); string(after) != string(before) {
		t.Errorf("the config changed:\n%s", after)
	}
}

func TestPrepareLeavesTheGitConfigOfAJJStoreAlone(t *testing.T) {
	r := jjRepo(t, false)
	notes, err := Prepare(context.Background(), Tools{Git: "git", JJ: "jj"}, r)
	if err != nil || len(notes) != 0 {
		t.Fatalf("Prepare = %q, %v", notes, err)
	}
	store := filepath.Join(r, ".jj", "repo", "store", "git")
	if _, err := os.Stat(filepath.Join(store, "objects", "info", "alternates")); err != nil {
		t.Errorf("jj's git store needs its alternates guard too: %v", err)
	}
}

func TestStoreAndRootFindTheMainRepository(t *testing.T) {
	r := repo(t)
	wt := filepath.Join(filepath.Dir(r), "wt")
	git(t, r, "worktree", "add", "-q", wt)
	j := jjRepo(t, false)
	ws := filepath.Join(filepath.Dir(j), "ws")
	jj(t, j, "workspace", "add", "--quiet", ws)
	plain := t.TempDir()

	for _, c := range []struct {
		name, path, store, root, linkedGit, linkedJJ string
	}{
		{name: "a git repository", path: r, store: filepath.Join(r, ".git"), root: r},
		{name: "a git store", path: filepath.Join(r, ".git"), root: r},
		{name: "a linked worktree", path: wt, store: filepath.Join(r, ".git"), root: r, linkedGit: filepath.Join(r, ".git")},
		{name: "a jj repository", path: j, store: filepath.Join(j, ".jj", "repo", "store", "git"), root: j},
		{name: "a jj store", path: filepath.Join(j, ".jj", "repo"), root: j},
		{name: "a secondary jj workspace", path: ws, root: j, linkedJJ: filepath.Join(j, ".jj", "repo")},
		{name: "a plain directory", path: plain, root: plain},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := Store(c.path); got != c.store {
				t.Errorf("Store = %q, want %q", got, c.store)
			}
			if got := Root(c.path); got != c.root {
				t.Errorf("Root = %q, want %q", got, c.root)
			}
			if git, jj := Linked(c.path); git != c.linkedGit || jj != c.linkedJJ {
				t.Errorf("Linked = %q, %q, want %q, %q", git, jj, c.linkedGit, c.linkedJJ)
			}
		})
	}
}

func TestPrepareUnpacksRefsSoTheJailNeverLocksTheStoresRoot(t *testing.T) {
	r := repo(t)
	git(t, r, "branch", "packed")
	git(t, r, "tag", "-a", "-m", "v1", "v1")
	git(t, r, "pack-refs", "--all")
	before := git(t, r, "for-each-ref", "--format=%(refname) %(objectname)")
	if _, err := Prepare(context.Background(), Tools{Git: "git"}, r); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(r, ".git", "packed-refs")); !os.IsNotExist(err) {
		t.Errorf("packed-refs stays: %v", err)
	}
	if after := git(t, r, "for-each-ref", "--format=%(refname) %(objectname)"); after != before {
		t.Errorf("refs changed:\n%s\nwant\n%s", after, before)
	}
	if _, err := os.Stat(filepath.Join(r, ".git", "refs", "heads", "packed")); err != nil {
		t.Errorf("the branch is not a loose ref: %v", err)
	}
}
