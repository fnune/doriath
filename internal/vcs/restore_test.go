package vcs

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRestorePutsMovedBranchesBackAndKeepsNewOnes(t *testing.T) {
	r := repo(t)
	git(t, r, "branch", "topic")
	before := git(t, r, "rev-parse", "HEAD")
	rec := &Record{Session: "s1"}
	f := start(t, rec, r)

	git(t, r, "commit", "-q", "--allow-empty", "-m", "the agent's work")
	git(t, r, "branch", "-f", "topic", "HEAD")
	git(t, r, "branch", "agent")
	out := f.finish()
	if got := rec.Repos[0].Moved; !slices.Equal(got, []string{"refs/heads/main", "refs/heads/topic"}) {
		t.Fatalf("moved = %v", got)
	}
	if !strings.Contains(out, "main, topic moved in "+r) || !strings.Contains(out, "doriath restore s1 main topic") {
		t.Errorf("the report must name the moved branches and the command: %q", out)
	}

	var restored strings.Builder
	if err := Restore(f.ctx, f.tools, rec, &restored); err != nil {
		t.Fatal(err)
	}
	for _, branch := range []string{"main", "topic"} {
		if got := git(t, r, "rev-parse", branch); got != before {
			t.Errorf("%s = %s, want %s", branch, got, before)
		}
		if !strings.Contains(restored.String(), branch+" is back at "+before[:12]) {
			t.Errorf("Restore output does not mention %s: %q", branch, restored.String())
		}
	}
	if git(t, r, "for-each-ref", "refs/doriath") != "" {
		t.Error("restore must drop the backup refs it used")
	}
	if git(t, r, "rev-parse", "agent") == before {
		t.Error("a branch the agent created must stay where the agent put it")
	}
}

func TestDropBackupsLeavesTheBranchesAlone(t *testing.T) {
	r := repo(t)
	rec := &Record{Session: "s1"}
	f := start(t, rec, r)
	git(t, r, "commit", "-q", "--allow-empty", "-m", "the agent's work")
	moved := git(t, r, "rev-parse", "HEAD")
	f.finish()
	if git(t, r, "for-each-ref", "refs/doriath") == "" {
		t.Fatal("the test needs a backup ref to drop")
	}

	if err := DropBackups(f.ctx, f.tools, rec); err != nil {
		t.Fatal(err)
	}
	if got := git(t, r, "for-each-ref", "refs/doriath"); got != "" {
		t.Errorf("backup refs stay: %s", got)
	}
	if got := git(t, r, "rev-parse", "main"); got != moved {
		t.Errorf("main = %s, want the agent's %s", got, moved)
	}
}

func TestRestoreReportsWhatItCouldNotPutBack(t *testing.T) {
	r := repo(t)
	head := git(t, r, "rev-parse", "HEAD")
	rec := &Record{Session: "s1", Repos: []Repo{
		{Path: "/gone", GitDir: filepath.Join(t.TempDir(), "gone.git"), Branches: map[string]string{"refs/heads/main": head}, Moved: []string{"refs/heads/main"}},
		{Path: r, GitDir: filepath.Join(r, ".git"), Bookmarks: map[string]string{"trunk": head}, MovedBookmarks: []string{"trunk"}},
		{Path: r, GitDir: filepath.Join(r, ".git"), Branches: map[string]string{"refs/heads/old": head}, Moved: []string{"refs/heads/old"}},
	}}
	var out strings.Builder
	err := Restore(context.Background(), Tools{Git: "git"}, rec, &out)
	if err == nil || !strings.Contains(err.Error(), "gone.git") || !strings.Contains(err.Error(), "restoring bookmark trunk needs jj") {
		t.Fatalf("err = %v", err)
	}
	if got := git(t, r, "rev-parse", "old"); got != head {
		t.Errorf("a failure in one repository must not stop the others: old = %q, output %q", got, out.String())
	}
}

func TestDropBackupsReportsAStoreItCannotChange(t *testing.T) {
	rec := &Record{Session: "s1", Repos: []Repo{{Path: "/gone", GitDir: filepath.Join(t.TempDir(), "gone.git"), Moved: []string{"refs/heads/main"}}}}
	if err := DropBackups(context.Background(), Tools{Git: "git"}, rec); err == nil {
		t.Fatal("a store git cannot open must be an error")
	}
}

func jj(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("jj", append([]string{"--repository", dir, "--color", "never"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("jj %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// jjRepo is a jj repository with one commit, main, on top of the root.
// jj keeps its git store inside .jj unless colocated.
func jjRepo(t *testing.T, colocate bool) string {
	t.Helper()
	if _, err := exec.LookPath("jj"); err != nil {
		t.Skip("jj not available")
	}
	config := filepath.Join(t.TempDir(), "jj.toml")
	if err := os.WriteFile(config, []byte("[user]\nname = \"t\"\nemail = \"t@e\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JJ_CONFIG", config)
	dir := filepath.Join(t.TempDir(), "repo")
	flag := "--no-colocate"
	if colocate {
		flag = "--colocate"
	}
	cmd := exec.Command("jj", "git", "init", flag, dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("jj git init: %v\n%s", err, out)
	}
	jj(t, dir, "commit", "-m", "first")
	jj(t, dir, "bookmark", "create", "main", "-r", "@-")
	return dir
}

func bookmarkTarget(t *testing.T, dir, name string) string {
	t.Helper()
	return jj(t, dir, "log", "--no-graph", "-r", name, "-T", "commit_id")
}

func TestRestorePutsMovedBookmarksBack(t *testing.T) {
	r := jjRepo(t, false)
	before := bookmarkTarget(t, r, "main")
	rec := &Record{Session: "s1"}
	f := startWith(t, Tools{Git: "git", JJ: "jj"}, rec, r)
	if got := rec.Repos[0].Bookmarks; got["main"] != before {
		t.Fatalf("bookmarks at the start = %v", got)
	}

	jj(t, r, "commit", "-m", "the agent's work")
	jj(t, r, "bookmark", "set", "main", "-r", "@-")
	jj(t, r, "bookmark", "create", "agent", "-r", "@-")
	out := f.finish()
	if got := rec.Repos[0].MovedBookmarks; !slices.Equal(got, []string{"main"}) {
		t.Fatalf("moved bookmarks = %v\n%s", got, out)
	}
	if !strings.Contains(out, "main") {
		t.Errorf("the report must name the moved bookmark: %q", out)
	}

	var restored strings.Builder
	if err := Restore(f.ctx, f.tools, rec, &restored); err != nil {
		t.Fatal(err)
	}
	if got := bookmarkTarget(t, r, "main"); got != before {
		t.Errorf("main = %s, want %s\n%s", got, before, restored.String())
	}
	if !strings.Contains(restored.String(), "bookmark main is back at "+before[:12]) {
		t.Errorf("Restore output: %q", restored.String())
	}
	if bookmarkTarget(t, r, "agent") == before {
		t.Error("a bookmark the agent created must stay")
	}
}

func TestFinishBringsBackTheJJStoreTheSessionDeleted(t *testing.T) {
	r := jjRepo(t, false)
	extra := filepath.Join(r, ".jj", "repo", "store", "extra")
	files := 0
	if err := filepath.WalkDir(extra, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			files++
		}
		return err
	}); err != nil || files == 0 {
		t.Fatalf("the test needs files in jj's extra store: %d, %v", files, err)
	}
	f := startWith(t, Tools{Git: "git", JJ: "jj"}, &Record{Session: "s1"}, r)
	if err := os.RemoveAll(extra); err != nil {
		t.Fatal(err)
	}
	f.finish()
	if _, err := os.Stat(extra); errors.Is(err, os.ErrNotExist) {
		t.Fatal("the extra store stays deleted")
	}
	if got := jj(t, r, "log", "--no-graph", "-r", "main", "-T", "description"); got != "first" {
		t.Errorf("jj cannot read main after the store came back: %q", got)
	}
}

// conflictMain points main at two new commits in concurrent operations, as
// two jj processes racing would, and returns one of them.
func conflictMain(t *testing.T, r string) string {
	t.Helper()
	commit := func(message string) string {
		jj(t, r, "new", "main", "-m", message)
		return bookmarkTarget(t, r, "@")
	}
	a, b := commit("a"), commit("b")
	op := jj(t, r, "op", "log", "--no-graph", "-n", "1", "-T", "id")
	jj(t, r, "bookmark", "set", "main", "-r", a)
	jj(t, r, "--at-op", op, "bookmark", "set", "main", "-r", b)
	if !strings.Contains(jj(t, r, "bookmark", "list", "main"), "conflicted") {
		t.Fatal("the test needs main conflicted")
	}
	return a
}

func TestRestoreSucceedsWhenABookmarkWasConflictedAtTheStart(t *testing.T) {
	r := jjRepo(t, false)
	a := conflictMain(t, r)
	rec := &Record{Session: "s1"}
	f := startWith(t, Tools{Git: "git", JJ: "jj"}, rec, r)

	jj(t, r, "bookmark", "set", "main", "-r", a)
	f.finish()
	if err := Restore(f.ctx, f.tools, rec, io.Discard); err != nil {
		t.Fatalf("a conflict cannot be put back, and must not fail the restore: %v", err)
	}
}

func TestRestoreResolvesABookmarkTheSessionLeftConflicted(t *testing.T) {
	r := jjRepo(t, false)
	before := bookmarkTarget(t, r, "main")
	rec := &Record{Session: "s1"}
	f := startWith(t, Tools{Git: "git", JJ: "jj"}, rec, r)

	conflictMain(t, r)
	f.finish()
	if got := rec.Repos[0].MovedBookmarks; !slices.Equal(got, []string{"main"}) {
		t.Fatalf("moved bookmarks = %v", got)
	}
	if err := Restore(f.ctx, f.tools, rec, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got := bookmarkTarget(t, r, "main"); got != before {
		t.Errorf("main = %s, want %s", got, before)
	}
}
