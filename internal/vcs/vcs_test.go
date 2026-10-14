package vcs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func repo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "init", "-q", "-b", "main")
	git(t, dir, "commit", "-q", "--allow-empty", "-m", "first")
	return dir
}

func TestFinishKeepsWhatTheSessionDeleted(t *testing.T) {
	r := repo(t)
	git(t, r, "checkout", "-q", "-b", "topic")
	git(t, r, "commit", "-q", "--allow-empty", "-m", "only on topic")
	topic := git(t, r, "rev-parse", "HEAD")
	git(t, r, "checkout", "-q", "main")
	ctx, tools := context.Background(), Tools{Git: "git"}
	backup := filepath.Join(t.TempDir(), "backup")
	rec := &Record{Session: "s1", Started: time.Now()}
	if err := Start(ctx, tools, backup, rec, []string{r}); err != nil {
		t.Fatal(err)
	}

	git(t, r, "branch", "-D", "-q", "topic")
	git(t, r, "reflog", "expire", "--expire=now", "--all")
	git(t, r, "prune", "--expire=now")
	if exec.Command("git", "-C", r, "cat-file", "-e", topic).Run() == nil {
		t.Fatal("the test needs the commit gone before Finish")
	}
	if err := Finish(ctx, tools, backup, rec, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got := git(t, r, "rev-parse", BackupRef("s1", "refs/heads/topic")); got != topic {
		t.Fatalf("backup ref = %q, want %q", got, topic)
	}
	if !rec.Finished || len(rec.Repos[0].Moved) != 1 {
		t.Fatalf("record: %+v", rec)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Error("the linked objects must go once refs keep them alive")
	}
	if err := Restore(ctx, tools, rec, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got := git(t, r, "rev-parse", "topic"); got != topic {
		t.Fatalf("topic after restore = %q", got)
	}
}

func TestFinishPointsAgentWorktreesBack(t *testing.T) {
	r := repo(t)
	ctx, tools := context.Background(), Tools{Git: "git"}
	backup := filepath.Join(t.TempDir(), "backup")
	rec := &Record{Session: "s1"}
	if err := Start(ctx, tools, backup, rec, []string{r}); err != nil {
		t.Fatal(err)
	}
	wt := filepath.Join(filepath.Dir(r), "wt")
	git(t, r, "worktree", "add", "-q", wt, "-b", "agent")
	commondir := filepath.Join(r, ".git", "worktrees", "wt", "commondir")
	if err := os.WriteFile(commondir, []byte("/tmp/elsewhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := Finish(ctx, tools, backup, rec, &out); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(commondir); string(data) != "../..\n" || !strings.Contains(out.String(), "pointed it back") {
		t.Fatalf("commondir %q, output %q", data, out.String())
	}
	if got := rec.Repos[0].AgentWorktrees; len(got) != 1 || got[0] != "wt" {
		t.Fatalf("agent worktrees = %v", got)
	}

	if _, ok := Merged(ctx, tools, rec.Repos[0], "wt"); !ok {
		t.Fatal("a worktree at the tip of main is merged")
	}
	if err := os.WriteFile(filepath.Join(wt, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := Merged(ctx, tools, rec.Repos[0], "wt"); ok {
		t.Fatal("a worktree with uncommitted files is not merged")
	}
	git(t, wt, "add", "f")
	git(t, wt, "commit", "-q", "-m", "agent work")
	if _, ok := Merged(ctx, tools, rec.Repos[0], "wt"); ok {
		t.Fatal("a commit only on the agent branch is not merged")
	}
	git(t, r, "merge", "-q", "agent")
	dir, ok := Merged(ctx, tools, rec.Repos[0], "wt")
	if !ok {
		t.Fatal("merged work is merged")
	}
	if err := RemoveWorktree(ctx, tools, rec.Repos[0], dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(wt); !os.IsNotExist(err) {
		t.Error("the worktree stays")
	}
	if exec.Command("git", "-C", r, "rev-parse", "--verify", "--quiet", "agent").Run() == nil {
		t.Error("the merged agent branch stays")
	}
}

func TestRecordRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d", "s1.json")
	rec := &Record{Session: "s1", Profile: "p", Repos: []Repo{{Path: "/r", Branches: map[string]string{"refs/heads/main": "abc"}}}}
	if err := rec.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || got.Repos[0].Branches["refs/heads/main"] != "abc" {
		t.Fatalf("Load = %+v, %v", got, err)
	}
}

func TestFinishDropsForgedLFSObjects(t *testing.T) {
	r := repo(t)
	ctx, tools := context.Background(), Tools{Git: "git"}
	rec := &Record{Session: "s1", Started: time.Now().Add(-time.Second)}
	if err := Start(ctx, tools, filepath.Join(t.TempDir(), "b"), rec, []string{r}); err != nil {
		t.Fatal(err)
	}
	content := []byte("real content\n")
	sum := sha256.Sum256(content)
	good := hex.EncodeToString(sum[:])
	forged := strings.Repeat("ab", 32)
	for name, data := range map[string][]byte{good: content, forged: []byte("agent content\n")} {
		p := filepath.Join(r, ".git", "lfs", "objects", name[:2], name[2:4], name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out strings.Builder
	if err := Finish(ctx, tools, filepath.Join(t.TempDir(), "b"), rec, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(r, ".git", "lfs", "objects", forged[:2], forged[2:4], forged)); !os.IsNotExist(err) {
		t.Error("the forged object stays")
	}
	if _, err := os.Stat(filepath.Join(r, ".git", "lfs", "objects", good[:2], good[2:4], good)); err != nil {
		t.Error("the genuine object must stay")
	}
	if !strings.Contains(out.String(), "does not match its name") {
		t.Errorf("output: %s", out.String())
	}
}
