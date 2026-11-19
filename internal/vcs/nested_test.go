package vcs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func nestedRepositoryThatRuns(t *testing.T, outer, name, marker string) {
	t.Helper()
	sub := filepath.Join(outer, name)
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, sub, "init", "-q", "-b", "main")
	git(t, sub, "commit", "-q", "--allow-empty", "-m", "nested")
	git(t, sub, "config", "core.fsmonitor", "touch "+marker+"; echo")
}

func gitStatusRuns(t *testing.T, dir, marker string) bool {
	t.Helper()
	cmd := execGit(dir, "status", "--porcelain")
	_ = cmd.Run()
	_, err := os.Stat(marker)
	return err == nil
}

func TestFinishSetsAsideANestedRepositoryTheAgentStaged(t *testing.T) {
	r := repo(t)
	marker := filepath.Join(t.TempDir(), "ran")
	f := start(t, &Record{Session: "s1", Writable: []string{r}}, r)
	nestedRepositoryThatRuns(t, r, "tools", marker)
	git(t, r, "add", "tools")
	_ = os.Remove(marker)
	out := f.finish()
	if gitStatusRuns(t, r, marker) {
		t.Fatal("git status on the host ran the config of the nested repository")
	}
	if _, err := os.Lstat(filepath.Join(r, "tools", ".git.doriath-s1")); err != nil {
		t.Errorf("the nested repository is not set aside: %v", err)
	}
	if !strings.Contains(out, "tools") || !strings.Contains(out, "set aside") {
		t.Errorf("Finish did not say what it did:\n%s", out)
	}
}

func TestFinishKeepsASubmoduleThatWasThereAtTheStart(t *testing.T) {
	r := repo(t)
	lib := repo(t)
	git(t, r, "-c", "protocol.file.allow=always", "submodule", "add", "-q", lib, "lib")
	git(t, r, "commit", "-q", "-m", "add lib")
	f := start(t, &Record{Session: "s2", Writable: []string{r}}, r)
	out := f.finish()
	if _, err := os.Lstat(filepath.Join(r, "lib", ".git")); err != nil {
		t.Errorf("the submodule of the repository lost its .git: %v\n%s", err, out)
	}
	if strings.Contains(out, "aside") {
		t.Errorf("Finish moved a submodule aside that was there at the start:\n%s", out)
	}
}

func TestFinishSetsAsideASubmoduleTheAgentAdded(t *testing.T) {
	r := repo(t)
	lib := repo(t)
	f := start(t, &Record{Session: "s3", Writable: []string{r}}, r)
	git(t, r, "-c", "protocol.file.allow=always", "submodule", "add", "-q", lib, "lib")
	out := f.finish()
	if _, err := os.Lstat(filepath.Join(r, ".git", "modules", "lib")); err == nil {
		t.Errorf("the store of the new submodule stays\n%s", out)
	}
	if _, err := os.Lstat(filepath.Join(r, "lib", ".git.doriath-s3")); err != nil {
		t.Errorf("the .git file of the new submodule stays: %v\n%s", err, out)
	}
}

func TestWatchSetsAsideANestedRepositoryWhenTheAgentStagesIt(t *testing.T) {
	r := repo(t)
	marker := filepath.Join(t.TempDir(), "ran")
	rec := &Record{Session: "s4", Writable: []string{r}}
	start(t, rec, r)
	watch(t, rec)
	nestedRepositoryThatRuns(t, r, "tools", marker)
	git(t, r, "add", "tools")
	_ = os.Remove(marker)
	eventually(t, "the nested repository is set aside", func() bool {
		_, err := os.Lstat(filepath.Join(r, "tools", ".git.doriath-s4"))
		return err == nil
	})
	if gitStatusRuns(t, r, marker) {
		t.Fatal("git status on the host ran the config of the nested repository")
	}
}

func TestWatchSetsAsideAStoreUnderModules(t *testing.T) {
	r := repo(t)
	rec := &Record{Session: "s5", Writable: []string{r}}
	start(t, rec, r)
	watch(t, rec)
	time.Sleep(100 * time.Millisecond)
	store := filepath.Join(r, ".git", "modules", "x")
	for _, d := range []string{"objects", "refs"} {
		if err := os.MkdirAll(filepath.Join(store, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(store, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the store is set aside", func() bool {
		_, err := os.Lstat(store + ".doriath-s5")
		return err == nil
	})
}

func TestMergedDoesNotRunWhatTheAgentPutInAWorktree(t *testing.T) {
	r := repo(t)
	marker := filepath.Join(t.TempDir(), "ran")
	git(t, r, "config", "filter.x.clean", "touch "+marker+"; cat")
	wt := filepath.Join(filepath.Dir(r), "wt")
	git(t, r, "worktree", "add", "-q", "--detach", wt)
	if err := os.WriteFile(filepath.Join(wt, "f"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, wt, "add", "f")
	git(t, wt, "commit", "-q", "-m", "f")
	git(t, r, "update-ref", "refs/heads/main", git(t, wt, "rev-parse", "HEAD"))
	git(t, wt, "checkout", "-q", "--detach", "main")
	if err := os.WriteFile(filepath.Join(wt, ".gitattributes"), []byte("* filter=x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, "f"), []byte("two\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(filepath.Join(wt, "f"), later, later); err != nil {
		t.Fatal(err)
	}
	if _, ok := Merged(t.Context(), Tools{Git: "git"}, Repo{Path: r, GitDir: filepath.Join(r, ".git")}, "wt"); ok {
		t.Error("Merged vouches for a worktree with changes")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("a filter ran on a file of the agent's worktree")
	}
}

func TestMergedRefusesAWorktreeWithAGitlink(t *testing.T) {
	r := repo(t)
	marker := filepath.Join(t.TempDir(), "ran")
	wt := filepath.Join(filepath.Dir(r), "wt")
	git(t, r, "worktree", "add", "-q", "--detach", wt)
	nestedRepositoryThatRuns(t, wt, "tools", marker)
	git(t, wt, "add", "tools")
	git(t, wt, "commit", "-q", "-m", "gitlink")
	git(t, r, "update-ref", "refs/heads/main", git(t, wt, "rev-parse", "HEAD"))
	if _, ok := Merged(t.Context(), Tools{Git: "git"}, Repo{Path: r, GitDir: filepath.Join(r, ".git")}, "wt"); ok {
		t.Error("Merged vouches for a worktree that holds a nested repository")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the config of the nested repository ran")
	}
}

func execGit(dir string, args ...string) *exec.Cmd {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null")
	return cmd
}
