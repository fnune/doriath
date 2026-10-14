package vcs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMergedRefusesWhatItCannotVouchFor(t *testing.T) {
	for _, c := range []struct {
		name   string
		branch string
		setup  func(t *testing.T, r, wt string)
	}{
		{
			name:   "a worktree with no admin directory",
			branch: "main",
			setup: func(t *testing.T, r, wt string) {
				if err := os.RemoveAll(filepath.Join(r, ".git", "worktrees", "wt")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:   "a checkout whose .git points at another store",
			branch: "main",
			setup: func(t *testing.T, r, wt string) {
				// A clone has the same commits, so only the pointer check
				// stops git from vouching for a worktree of another store.
				evil := filepath.Join(t.TempDir(), "evil")
				git(t, r, "clone", "-q", r, evil)
				git(t, evil, "worktree", "add", "-q", "--detach", filepath.Join(t.TempDir(), "evilwt"))
				admin := filepath.Join(evil, ".git", "worktrees", "evilwt")
				if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: "+admin+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:   "a repository with no default branch",
			branch: "trunk",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := repo(t)
			git(t, r, "branch", "-m", c.branch)
			wt := filepath.Join(filepath.Dir(r), "wt")
			git(t, r, "worktree", "add", "-q", "--detach", wt)
			if c.setup != nil {
				c.setup(t, r, wt)
			}
			if _, ok := Merged(t.Context(), Tools{Git: "git"}, Repo{Path: r, GitDir: filepath.Join(r, ".git")}, "wt"); ok {
				t.Fatal("Merged = true")
			}
		})
	}
}

func TestMergedFollowsTheRemoteDefaultBranch(t *testing.T) {
	r := repo(t)
	git(t, r, "branch", "-m", "trunk")
	git(t, r, "update-ref", "refs/remotes/origin/trunk", "HEAD")
	git(t, r, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/trunk")
	wt := filepath.Join(filepath.Dir(r), "wt")
	git(t, r, "worktree", "add", "-q", "--relative-paths", wt, "-b", "agent")
	if data, _ := os.ReadFile(filepath.Join(r, ".git", "worktrees", "wt", "gitdir")); filepath.IsAbs(strings.TrimSpace(string(data))) {
		t.Fatalf("the test needs a relative gitdir: %q", data)
	}
	repo := Repo{Path: r, GitDir: filepath.Join(r, ".git")}

	dir, ok := Merged(t.Context(), Tools{Git: "git"}, repo, "wt")
	if !ok || dir != wt {
		t.Fatalf("Merged = %q, %v, want %q, true", dir, ok, wt)
	}
	git(t, wt, "commit", "-q", "--allow-empty", "-m", "agent work")
	git(t, r, "merge", "-q", "--ff-only", "agent")
	if _, ok := Merged(t.Context(), Tools{Git: "git"}, repo, "wt"); ok {
		t.Fatal("work merged locally but not in origin's default branch is not merged")
	}
}
