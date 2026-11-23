//go:build integration

package session_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/vcs"
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

func TestStoreOfAReadOnlyRepository(t *testing.T) {
	e := newEnv(t)
	repo := filepath.Join(e.home, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "init", "-q", "-b", "main")
	git(t, repo, "commit", "-q", "--allow-empty", "-m", "first")
	git(t, repo, "branch", "feature")
	git(t, repo, "branch", "spare")
	git(t, repo, "checkout", "-q", "-b", "gone")
	git(t, repo, "commit", "-q", "--allow-empty", "-m", "only on gone")
	gone := git(t, repo, "rev-parse", "HEAD")
	git(t, repo, "checkout", "-q", "main")
	git(t, repo, "worktree", "add", "-q", filepath.Join(e.home, "user-wt"), "feature")
	spare := git(t, repo, "rev-parse", "spare")
	git(t, repo, "pack-refs", "--all")

	p := e.profile(fmt.Sprintf("\n[[mounts]]\npath = %q\nmode = \"read\"\n\n[vcs]\nstore = true\n", repo))
	code, out := e.run(p, fmt.Sprintf(`
set -u
R=%[1]s
export GIT_AUTHOR_NAME=a GIT_AUTHOR_EMAIL=a@b GIT_COMMITTER_NAME=a GIT_COMMITTER_EMAIL=a@b
git -C $R worktree add -q /tmp/wt -b agent || echo "FAIL worktree add"
cd /tmp/wt && echo x > f && git add f && git commit -qm agent || echo "FAIL commit"
git -C $R branch -f spare agent || echo "FAIL move a branch"
git -C $R branch -q -D gone || echo "FAIL delete a packed branch"
git -C $R prune --expire=now || echo "FAIL prune"
echo x >> $R/.git/config 2>/dev/null && echo "FAIL config writable"
touch $R/.git/hooks/post-checkout 2>/dev/null && echo "FAIL hooks writable"
echo /tmp > $R/.git/commondir 2>/dev/null && sleep 1 && [ -e $R/.git/commondir ] && echo "FAIL commondir stayed"
echo /tmp > $R/.git/worktrees/user-wt/commondir 2>/dev/null && echo "FAIL user worktree commondir"
echo x > $R/README 2>/dev/null && echo "FAIL checkout writable"
echo /tmp/elsewhere > $R/.git/worktrees/wt/commondir || echo "FAIL own worktree admin"
echo done
`, repo), nil)
	if code != 0 || !strings.Contains(out, "done") || strings.Contains(out, "FAIL") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if !strings.Contains(out, "gone, spare moved in") || !strings.Contains(out, "doriath restore "+e.lastID) {
		t.Errorf("the session must report the moved branches:\n%s", out)
	}
	if got := git(t, repo, "rev-parse", "agent"); got == "" {
		t.Error("the agent's branch is missing")
	}
	saved, err := vcs.Load(filepath.Join(e.paths.Backups(), e.lastID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := git(t, repo, "rev-parse", saved.BackupRef("refs/heads/gone")); got != gone {
		t.Errorf("start value of gone = %q, want %q", got, gone)
	}
	if got := git(t, repo, "cat-file", "-t", gone); got != "commit" {
		t.Errorf("the pruned commit must be back: %q", got)
	}
	if data, _ := os.ReadFile(filepath.Join(repo, ".git", "worktrees", "wt", "commondir")); strings.TrimSpace(string(data)) != "../.." {
		t.Errorf("the agent worktree's commondir must be reset, is %q", data)
	}

	rec, err := vcs.Load(filepath.Join(e.paths.Backups(), e.lastID+".json"))
	if err != nil || !rec.Finished {
		t.Fatalf("record: %+v, %v", rec, err)
	}
	if err := vcs.Restore(context.Background(), vcs.Tools{Git: "git"}, rec, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got := git(t, repo, "rev-parse", "spare"); got != spare {
		t.Errorf("spare after restore = %q, want %q", got, spare)
	}
	if got := git(t, repo, "rev-parse", "gone"); got != gone {
		t.Errorf("gone after restore = %q, want %q", got, gone)
	}
	if got := git(t, repo, "rev-parse", "agent"); got == "" {
		t.Error("restore must leave the agent's own branch")
	}
}

func TestStoreOfAReadOnlyJJRepository(t *testing.T) {
	jj, err := exec.LookPath("jj")
	if err != nil {
		t.Skip("jj not available")
	}
	if real, err := filepath.EvalSymlinks(jj); err == nil {
		jj = real
	}
	e := newEnv(t)
	repo := filepath.Join(e.home, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	jjRun := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(jj, append([]string{"--repository", repo, "--config", "user.name=t", "--config", "user.email=t@e"}, args...)...)
		cmd.Env = append(os.Environ(), "JJ_CONFIG=/dev/null")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("jj %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	cmd := exec.Command(jj, "git", "init", "--colocate", repo)
	cmd.Env = append(os.Environ(), "JJ_CONFIG=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("jj git init: %v\n%s", err, out)
	}
	jjRun("describe", "-m", "first")
	jjRun("bookmark", "create", "main", "-r", "@")
	jjRun("new")
	if err := os.Remove(filepath.Join(repo, ".jj", "repo", "git_import_export.lock")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	config, err := os.ReadFile(filepath.Join(repo, ".git", "config"))
	if err != nil {
		t.Fatal(err)
	}
	p := e.profile(fmt.Sprintf(`
[[mounts]]
path = %q
mode = "read"

[vcs]
store = true
`, repo))
	code, out := e.run(p, fmt.Sprintf(`
set -u
J="%[1]s --config user.name=a --config user.email=a@b"
R=%[2]s
$J --repository $R log -r 'all()' --no-graph -T 'description' >/dev/null || echo "FAIL log in the read-only checkout"
$J --repository $R workspace add /tmp/ws || echo "FAIL workspace add"
case "$(cat $R/.git/worktrees/ws/gitdir)" in /*) ;; *) echo "FAIL relative worktree path" ;; esac
cd /tmp/ws && echo x > f && $J describe -m agent && $J new && $J bookmark create agent -r @- || echo "FAIL commit in the workspace"
echo x >> $R/.jj/repo/store/git_target 2>/dev/null && echo "FAIL git_target writable"
touch $R/.jj/repo/store/planted 2>/dev/null && echo "FAIL store writable"
echo '[ui]' > $R/.jj/repo/config.toml 2>/dev/null && echo "FAIL repo config created"
echo x > $R/README 2>/dev/null && echo "FAIL checkout writable"
echo done
`, jj, repo), nil)
	if code != 0 || !strings.Contains(out, "done") || strings.Contains(out, "FAIL") || strings.Contains(out, "Failed to take lock") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if now, err := os.ReadFile(filepath.Join(repo, ".git", "config")); err != nil || !bytes.Equal(now, config) {
		t.Errorf("adding a workspace changed .git/config:\n%s", now)
	}
	if !strings.Contains(jjRun("bookmark", "list"), "agent") {
		t.Errorf("the agent's bookmark is missing:\n%s", jjRun("bookmark", "list"))
	}
}

func TestProjectFromTheStartDirectory(t *testing.T) {
	e := newEnv(t)
	repo := filepath.Join(e.home, "app")
	if err := os.MkdirAll(filepath.Join(repo, "pkg"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "README"), []byte("top\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "init", "-q", "-b", "main")
	git(t, repo, "add", "README")
	git(t, repo, "commit", "-q", "-m", "first")
	e.cwd = filepath.Join(repo, "pkg")
	p := e.profile("\n[[mounts]]\npath = \"{repository}/.agent/worktrees\"\nmode = \"write\"\n\n[vcs]\nstore = true\n")
	code, out := e.run(p, fmt.Sprintf(`
set -u
export GIT_AUTHOR_NAME=a GIT_AUTHOR_EMAIL=a@b GIT_COMMITTER_NAME=a GIT_COMMITTER_EMAIL=a@b
test "$PWD" = %[1]s/pkg || echo "FAIL started in $PWD"
grep -q top ../README || echo "FAIL the repository root is not visible"
touch ../new 2>/dev/null && echo "FAIL the checkout is writable"
git worktree add -q %[1]s/.agent/worktrees/w -b agent || echo "FAIL worktree add"
cd %[1]s/.agent/worktrees/w && echo x > f && git add f && git commit -qm agent || echo "FAIL commit"
echo done
`, repo), nil)
	if code != 0 || !strings.Contains(out, "done") || strings.Contains(out, "FAIL") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if got := git(t, repo, "log", "-1", "--format=%s", "agent"); got != "agent" {
		t.Errorf("agent branch head = %q", got)
	}
}

func TestStartInALinkedWorktree(t *testing.T) {
	e := newEnv(t)
	repo := filepath.Join(e.home, "repo")
	trees := filepath.Join(e.home, ".worktrees", "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "init", "-q", "-b", "main")
	git(t, repo, "commit", "-q", "--allow-empty", "-m", "first")
	git(t, repo, "worktree", "add", "-q", filepath.Join(trees, "feat"), "-b", "feat")
	e.cwd = filepath.Join(trees, "feat")
	p := e.profile(fmt.Sprintf("\n[[mounts]]\npath = %q\nmode = \"write\"\n\n[vcs]\nstore = true\n", trees))
	code, out := e.run(p, fmt.Sprintf(`
set -u
export GIT_AUTHOR_NAME=a GIT_AUTHOR_EMAIL=a@b GIT_COMMITTER_NAME=a GIT_COMMITTER_EMAIL=a@b
git log --oneline -1 >/dev/null || echo "FAIL git in the linked worktree"
git worktree add -q %[1]s/agent -b agent || echo "FAIL worktree add"
cd %[1]s/agent && echo x > f && git add f && git commit -qm agent || echo "FAIL commit"
echo x >> %[2]s/.git/config 2>/dev/null && echo "FAIL the main config is writable"
echo done
`, trees, repo), nil)
	if code != 0 || !strings.Contains(out, "done") || strings.Contains(out, "FAIL") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if got := git(t, repo, "log", "-1", "--format=%s", "agent"); got != "agent" {
		t.Errorf("agent branch head = %q", got)
	}
}

func TestStartInAJJWorkspace(t *testing.T) {
	jj, err := exec.LookPath("jj")
	if err != nil {
		t.Skip("jj not available")
	}
	if real, err := filepath.EvalSymlinks(jj); err == nil {
		jj = real
	}
	e := newEnv(t)
	repo := filepath.Join(e.home, "repo")
	trees := filepath.Join(e.home, ".worktrees", "repo")
	for _, d := range []string{repo, trees} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command(jj, append([]string{"--config", "user.name=t", "--config", "user.email=t@e"}, args...)...)
		cmd.Dir, cmd.Env = dir, append(os.Environ(), "JJ_CONFIG=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("jj %v: %v\n%s", args, err, out)
		}
	}
	run(e.home, "git", "init", "--colocate", repo)
	run(repo, "describe", "-m", "first")
	run(repo, "workspace", "add", filepath.Join(trees, "feat"))
	e.cwd = filepath.Join(trees, "feat")
	p := e.profile(fmt.Sprintf("\n[[mounts]]\npath = %q\nmode = \"write\"\n\n[vcs]\nstore = true\n", trees))
	code, out := e.run(p, fmt.Sprintf(`
set -u
J="%[1]s --config user.name=a --config user.email=a@b"
$J log -r @ --no-graph -T 'change_id' >/dev/null || echo "FAIL jj in the workspace"
echo x > f && $J describe -m agent || echo "FAIL describe"
echo done
`, jj), nil)
	if code != 0 || !strings.Contains(out, "done") || strings.Contains(out, "FAIL") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}

func TestRequestEditChangesSafeSettingsAndAsksForTheRest(t *testing.T) {
	e := newEnv(t)
	e.hostWait = 30 * time.Second
	repo := filepath.Join(e.home, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "init", "-q", "-b", "main")
	git(t, repo, "commit", "-q", "--allow-empty", "-m", "first")
	git(t, repo, "remote", "add", "origin", "https://example.com/repo.git")
	p := e.profile(fmt.Sprintf(`
[[mounts]]
path = %q
mode = "read"

[[mounts]]
path = "{git}/config"
edit = { format = "git-config", safe = ["branch.*.remote = *", "branch.*.merge = refs/heads/**"] }

[vcs]
store = true
`, repo))
	var asked approval.Request
	code, out := e.run(p, fmt.Sprintf(`
R=%[1]s
git -C $R config branch.main.remote origin 2>/dev/null && echo "FAIL config writable"
cp $R/.git/config /tmp/c
git config --file /tmp/c branch.main.remote origin
git config --file /tmp/c branch.main.merge refs/heads/main
/run/doriath-bin/doriath request edit $R/.git/config < /tmp/c || echo "FAIL safe edit"
[ "$(git -C $R config branch.main.merge)" = refs/heads/main ] || echo "FAIL the jail sees the old config"
git config --file /tmp/c core.fsmonitor /tmp/evil
/run/doriath-bin/doriath request edit $R/.git/config --reason "watch files" < /tmp/c && echo "FAIL unsafe edit applied"
echo done
`, repo), func() {
		asked = e.decideNext(approval.Decision{Verdict: approval.VerdictDeny, By: "test"})
	})
	if code != 0 || !strings.Contains(out, "done") || strings.Contains(out, "FAIL") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if got := git(t, repo, "config", "branch.main.merge"); got != "refs/heads/main" {
		t.Errorf("branch.main.merge = %q\n%s", got, out)
	}
	cmd := exec.Command("git", "-C", repo, "config", "core.fsmonitor")
	if v, err := cmd.Output(); err == nil {
		t.Errorf("core.fsmonitor = %q after a denial", v)
	}
	if asked.Kind != approval.KindEdit || !strings.Contains(asked.Details, "core.fsmonitor = /tmp/evil  (not on the safe list)") || strings.Contains(asked.Details, "branch.main") {
		t.Errorf("request = %+v", asked)
	}
}

func TestASessionStartsWhenItsGuardsTakeMoreThanNineThousandArguments(t *testing.T) {
	e := newEnv(t)
	repo := filepath.Join(e.work, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "init", "-q", "-b", "main")
	for i := range 1000 {
		admin := filepath.Join(repo, ".git", "worktrees", fmt.Sprintf("wt%d", i))
		if err := os.MkdirAll(admin, 0o700); err != nil {
			t.Fatal(err)
		}
		files := map[string]string{
			"commondir":       "../..\n",
			"gitdir":          filepath.Join(e.home, fmt.Sprintf("wt%d", i), ".git") + "\n",
			"config.worktree": "",
		}
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(admin, name), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	code, out := e.run(e.profile(""), `echo started`, nil)
	if code != 0 || !strings.Contains(out, "started") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}
