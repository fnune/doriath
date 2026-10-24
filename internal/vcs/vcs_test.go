package vcs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

// fixture is a session that started on a repository and has yet to finish.
type fixture struct {
	t      *testing.T
	ctx    context.Context
	tools  Tools
	backup string
	rec    *Record
}

func start(t *testing.T, rec *Record, repos ...string) *fixture {
	t.Helper()
	return startWith(t, Tools{Git: "git"}, rec, repos...)
}

func startWith(t *testing.T, tools Tools, rec *Record, repos ...string) *fixture {
	t.Helper()
	f := &fixture{t: t, ctx: context.Background(), tools: tools, backup: filepath.Join(t.TempDir(), "backup"), rec: rec}
	if err := Start(f.ctx, tools, f.backup, rec, repos); err != nil {
		t.Fatal(err)
	}
	return f
}

// finish ends the session and returns what it told the person.
func (f *fixture) finish() string {
	f.t.Helper()
	var out strings.Builder
	if err := Finish(f.ctx, f.tools, f.backup, f.rec, &out); err != nil {
		f.t.Fatalf("Finish: %v\n%s", err, out.String())
	}
	return out.String()
}

func TestFinishKeepsWhatTheSessionDeleted(t *testing.T) {
	r := repo(t)
	git(t, r, "checkout", "-q", "-b", "topic")
	git(t, r, "commit", "-q", "--allow-empty", "-m", "only on topic")
	topic := git(t, r, "rev-parse", "HEAD")
	git(t, r, "checkout", "-q", "main")
	rec := &Record{Session: "s1", Started: time.Now()}
	f := start(t, rec, r)

	git(t, r, "branch", "-D", "-q", "topic")
	git(t, r, "reflog", "expire", "--expire=now", "--all")
	git(t, r, "prune", "--expire=now")
	if exec.Command("git", "-C", r, "cat-file", "-e", topic).Run() == nil {
		t.Fatal("the test needs the commit gone before Finish")
	}
	f.finish()
	if got := git(t, r, "rev-parse", BackupRef("s1", "refs/heads/topic")); got != topic {
		t.Fatalf("backup ref = %q, want %q", got, topic)
	}
	if !rec.Finished || len(rec.Repos[0].Moved) != 1 {
		t.Fatalf("record: %+v", rec)
	}
	if _, err := os.Stat(f.backup); !os.IsNotExist(err) {
		t.Error("the linked objects must go once refs keep them alive")
	}
	if err := Restore(f.ctx, f.tools, rec, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got := git(t, r, "rev-parse", "topic"); got != topic {
		t.Fatalf("topic after restore = %q", got)
	}
}

func TestFinishPointsAgentWorktreesBack(t *testing.T) {
	r := repo(t)
	rec := &Record{Session: "s1"}
	f := start(t, rec, r)
	wt := filepath.Join(filepath.Dir(r), "wt")
	git(t, r, "worktree", "add", "-q", wt, "-b", "agent")
	commondir := filepath.Join(r, ".git", "worktrees", "wt", "commondir")
	if err := os.WriteFile(commondir, []byte("/tmp/elsewhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := f.finish()
	if data, _ := os.ReadFile(commondir); string(data) != "../..\n" || !strings.Contains(out, "pointed it back") {
		t.Fatalf("commondir %q, output %q", data, out)
	}
	if got := rec.Repos[0].AgentWorktrees; len(got) != 1 || got[0] != "wt" {
		t.Fatalf("agent worktrees = %v", got)
	}

	if _, ok := Merged(f.ctx, f.tools, rec.Repos[0], "wt"); !ok {
		t.Fatal("a worktree at the tip of main is merged")
	}
	if err := os.WriteFile(filepath.Join(wt, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := Merged(f.ctx, f.tools, rec.Repos[0], "wt"); ok {
		t.Fatal("a worktree with uncommitted files is not merged")
	}
	git(t, wt, "add", "f")
	git(t, wt, "commit", "-q", "-m", "agent work")
	if _, ok := Merged(f.ctx, f.tools, rec.Repos[0], "wt"); ok {
		t.Fatal("a commit only on the agent branch is not merged")
	}
	git(t, r, "merge", "-q", "agent")
	dir, ok := Merged(f.ctx, f.tools, rec.Repos[0], "wt")
	if !ok {
		t.Fatal("merged work is merged")
	}
	if err := RemoveWorktree(f.ctx, f.tools, rec.Repos[0], dir); err != nil {
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
	f := start(t, &Record{Session: "s1", Started: time.Now().Add(-time.Second)}, r)
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
		long := time.Now().Add(-24 * time.Hour)
		if err := os.Chtimes(p, long, long); err != nil {
			t.Fatal(err)
		}
	}
	linked := strings.Repeat("cd", 32)
	linkPath := filepath.Join(r, ".git", "lfs", "objects", linked[:2], linked[2:4], linked)
	if err := os.MkdirAll(filepath.Dir(linkPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", linkPath); err != nil {
		t.Fatal(err)
	}
	out := f.finish()
	if _, err := os.Stat(filepath.Join(r, ".git", "lfs", "objects", forged[:2], forged[2:4], forged)); !os.IsNotExist(err) {
		t.Error("the forged object stays, though the agent set its time back")
	}
	if _, err := os.Lstat(linkPath); !os.IsNotExist(err) {
		t.Error("a symlink among LFS objects stays")
	}
	if _, err := os.Stat(filepath.Join(r, ".git", "lfs", "objects", good[:2], good[2:4], good)); err != nil {
		t.Error("the genuine object must stay")
	}
	if !strings.Contains(out, "does not match its name") {
		t.Errorf("output: %s", out)
	}
}

func TestFinishRepairsAgentWorktrees(t *testing.T) {
	r := repo(t)
	trees := filepath.Join(filepath.Dir(r), "trees")
	f := start(t, &Record{Session: "s1", Writable: []string{trees}}, r)
	for _, name := range []string{"redirected", "replaced"} {
		git(t, r, "worktree", "add", "-q", filepath.Join(trees, name), "-b", name)
	}
	evil := filepath.Join(t.TempDir(), "evil.git")
	if err := os.WriteFile(filepath.Join(trees, "redirected", ".git"), []byte("gitdir: "+evil+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(trees, "replaced", ".git")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(trees, "replaced", ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r, ".git", "worktrees", "redirected", "config.worktree"), []byte("[core]\nfsmonitor = /tmp/x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := f.finish()
	for _, name := range []string{"redirected", "replaced"} {
		if !pointsTo(filepath.Join(trees, name), filepath.Join(r, ".git", "worktrees", name)) {
			t.Errorf("%s still points elsewhere:\n%s", name, out)
		}
	}
	if _, err := os.Stat(filepath.Join(trees, "replaced", ".git.doriath-s1", "hooks")); err != nil {
		t.Error("the agent's .git directory must be kept aside, not deleted")
	}
	if data, err := os.ReadFile(filepath.Join(r, ".git", "worktrees", "redirected", "config.worktree")); err != nil || len(data) != 0 {
		t.Errorf("a planted config.worktree must be emptied in place: %q, %v", data, err)
	}
	if got := git(t, filepath.Join(trees, "redirected"), "rev-parse", "--abbrev-ref", "HEAD"); got != "redirected" {
		t.Errorf("git in the repaired worktree: %q", got)
	}
}

// Another session binds an empty config.worktree read-only into its jail;
// removing it, or emptying the file another name points at, would undo
// that session's guard or the agent's other file.
func TestFinishEmptiesWorktreeConfigsInPlace(t *testing.T) {
	r := repo(t)
	trees := filepath.Join(filepath.Dir(r), "trees")
	f := start(t, &Record{Session: "s1", Writable: []string{trees}}, r)
	for _, name := range []string{"held", "planted", "linked"} {
		git(t, r, "worktree", "add", "-q", filepath.Join(trees, name), "-b", name)
	}
	config := func(name string) string { return filepath.Join(r, ".git", "worktrees", name, "config.worktree") }
	if err := os.WriteFile(config("held"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config("planted"), []byte("[core]\nfsmonitor = /tmp/x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(other, []byte("[core]\nfsmonitor = /tmp/x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(other, config("linked")); err != nil {
		t.Fatal(err)
	}
	held, err := os.Stat(config("held"))
	if err != nil {
		t.Fatal(err)
	}
	planted, err := os.Stat(config("planted"))
	if err != nil {
		t.Fatal(err)
	}

	out := f.finish()
	if now, err := os.Stat(config("held")); err != nil || !os.SameFile(held, now) || now.Size() != 0 {
		t.Errorf("the empty config of another session must stay as it is: %v\n%s", err, out)
	}
	if strings.Contains(out, "worktree held") {
		t.Errorf("an empty config was reported as the agent's:\n%s", out)
	}
	if now, err := os.Stat(config("planted")); err != nil || !os.SameFile(planted, now) || now.Size() != 0 {
		t.Errorf("a config with settings must be emptied in place: %v\n%s", err, out)
	}
	if _, err := os.Lstat(config("linked")); !os.IsNotExist(err) {
		t.Errorf("a config with another link must be removed: %v", err)
	}
	if data, err := os.ReadFile(other); err != nil || len(data) == 0 {
		t.Errorf("the file behind the other link changed: %q, %v", data, err)
	}
}

func TestFinishDoesNotRepairThroughLinks(t *testing.T) {
	r := repo(t)
	trees := filepath.Join(filepath.Dir(r), "trees")
	ctx, tools := context.Background(), Tools{Git: "git"}
	backup := filepath.Join(t.TempDir(), "b")
	rec := &Record{Session: "s1", Writable: []string{trees}}
	if err := Start(ctx, tools, backup, rec, []string{r}); err != nil {
		t.Fatal(err)
	}
	victim := t.TempDir()
	for _, f := range []string{"commondir", "config.worktree"} {
		if err := os.WriteFile(filepath.Join(victim, f), []byte("yours\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(r, ".git", "worktrees"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(r, ".git", "worktrees", "linked")); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.MkdirAll(trees, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(trees, "out")); err != nil {
		t.Fatal(err)
	}
	git(t, r, "worktree", "add", "-q", filepath.Join(trees, "real"), "-b", "real")
	admin := filepath.Join(r, ".git", "worktrees", "real")
	if err := os.WriteFile(filepath.Join(admin, "gitdir"), []byte(filepath.Join(trees, "out", "x", ".git")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(outside, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := Finish(ctx, tools, backup, rec, &out); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"commondir", "config.worktree"} {
		if data, err := os.ReadFile(filepath.Join(victim, f)); err != nil || string(data) != "yours\n" {
			t.Errorf("%s behind the link changed: %q, %v\n%s", f, data, err, out.String())
		}
	}
	if _, err := os.Lstat(filepath.Join(r, ".git", "worktrees", "linked")); !os.IsNotExist(err) {
		t.Error("the linked admin directory must go")
	}
	if _, err := os.Lstat(filepath.Join(outside, "x", ".git")); !os.IsNotExist(err) {
		t.Errorf("doriath wrote a .git through a link in the checkout path:\n%s", out.String())
	}
}

func TestFinishLeavesWorktreesOutsideTheSessionAlone(t *testing.T) {
	r := repo(t)
	f := start(t, &Record{Session: "s1", Writable: []string{filepath.Join(t.TempDir(), "elsewhere")}}, r)
	other := filepath.Join(filepath.Dir(r), "yours")
	git(t, r, "worktree", "add", "-q", other, "-b", "yours")
	if err := os.WriteFile(filepath.Join(other, ".git"), []byte("gitdir: /somewhere/else\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := f.finish()
	if data, _ := os.ReadFile(filepath.Join(other, ".git")); string(data) != "gitdir: /somewhere/else\n" || !strings.Contains(out, "left it alone") {
		t.Fatalf("a checkout outside the session must not be rewritten: %q\n%s", data, out)
	}
}

func TestFinishRestoresARewrittenLooseObject(t *testing.T) {
	r := repo(t)
	head := git(t, r, "rev-parse", "HEAD")
	rec := &Record{Session: "s1"}
	f := start(t, rec, r)
	obj := filepath.Join(r, ".git", "objects", head[:2], head[2:])
	if err := os.Chmod(obj, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(obj, []byte("corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.finish()
	if got := git(t, r, "cat-file", "-t", head); got != "commit" {
		t.Fatalf("the rewritten object was not restored: %q", got)
	}
}

func TestFinishKeepsTheBackupUntilItSucceeds(t *testing.T) {
	r := repo(t)
	rec := &Record{Session: "s1"}
	f := start(t, rec, r)
	head := filepath.Join(r, ".git", "HEAD")
	if err := os.WriteFile(head, []byte("not a ref\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Finish(f.ctx, f.tools, f.backup, rec, io.Discard); err == nil {
		t.Fatal("Finish must report a store git cannot read")
	}
	if _, err := os.Stat(f.backup); err != nil || rec.Finished {
		t.Fatalf("a failed Finish must keep the backup for the next try: %v, finished %v", err, rec.Finished)
	}

	if err := os.WriteFile(head, []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.finish()
	if !rec.Finished {
		t.Error("the second Finish must complete")
	}
}

func TestFinishSetsAsideWhatTheAgentLeftForGitToContinue(t *testing.T) {
	r := repo(t)
	gitDir := filepath.Join(r, ".git")
	yours := filepath.Join(gitDir, "sequencer")
	if err := os.MkdirAll(yours, 0o755); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	rec := &Record{Session: "s1", Started: time.Now()}
	f := start(t, rec, r)
	todo := filepath.Join(gitDir, "rebase-merge", "git-rebase-todo")
	module := filepath.Join(gitDir, "modules", "lib")
	rerere := filepath.Join(gitDir, "rr-cache")
	for _, d := range []string{filepath.Dir(todo), filepath.Join(module, "objects"), filepath.Join(rerere, "planted")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(todo, []byte("exec touch /tmp/pwned\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"HEAD": "ref: refs/heads/main\n", "config": "[core]\n\tfsmonitor = touch /tmp/pwned\n"} {
		if err := os.WriteFile(filepath.Join(module, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := f.finish()
	for p, why := range map[string]string{
		filepath.Dir(todo): "git rebase --continue runs its exec lines",
		module:             "git submodule update takes it up with its config",
		rerere:             "its presence alone turns on rerere for your next merge",
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s is still there, and %s:\n%s", p, why, out)
		}
		if !isDir(p + ".doriath-s1") {
			t.Errorf("%s must be kept aside, not deleted", p)
		}
	}
	if !isDir(yours) {
		t.Error("the cherry-pick you had in progress before the session must stay")
	}
}

func TestTheBackupSkipsFilesThatGitRemovesWhileItCopies(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	for i := range 200 {
		dir := filepath.Join(src, fmt.Sprintf("%02x", i))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "object"), []byte("content"), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			lock := filepath.Join(src, "maintenance.lock")
			_ = os.WriteFile(lock, nil, 0o600)
			_ = os.Remove(lock)
			tmp := filepath.Join(src, fmt.Sprintf("%02x", i%200), "tmp_obj")
			_ = os.WriteFile(tmp, nil, 0o600)
			_ = os.Remove(tmp)
		}
	}()
	defer func() { close(stop); <-done }()
	for i := range 50 {
		target := filepath.Join(dst, fmt.Sprint(i))
		if err := mirror(src, target); err != nil {
			t.Fatalf("copy %d: %v", i, err)
		}
		if _, err := os.Stat(filepath.Join(target, "maintenance.lock")); err == nil {
			t.Fatal("the backup copied git's lock file")
		}
	}
}

func TestAFinishedSessionWhoseRepositoryIsGoneIsFinished(t *testing.T) {
	gone := filepath.Join(t.TempDir(), "repo")
	rec := &Record{Session: "s1", Repos: []Repo{{Path: gone, GitDir: filepath.Join(gone, ".git")}}}
	var out bytes.Buffer
	if err := Finish(context.Background(), Tools{Git: "git"}, filepath.Join(t.TempDir(), "backup"), rec, &out); err != nil {
		t.Fatalf("err = %v", err)
	}
	if !rec.Finished || !strings.Contains(out.String(), "is gone") {
		t.Errorf("finished = %v, out = %q", rec.Finished, out.String())
	}
}
