//go:build integration

package session_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// knownGaps are operations of the survey that fail in the jail, with why.
// The survey fails on any other failure, and on a gap that starts to work.
var knownGaps = map[string]string{
	"git-remote-add":      "a remote's URL decides where pushes go, so doriath asks you first, and nobody answers here",
	"jj-git-remote-add":   "jj writes git's config in its own process, past doriath's git; git remote add works",
	"git-config-local":    "any setting may name a program, so the agent asks with doriath request edit",
	"git-sparse-checkout": "it needs extensions.worktreeConfig in .git/config and a config.worktree for the worktree",
}

// surveyOps runs each operation in the jail and prints OK or FAIL with the
// end of its output. Later operations build on earlier ones, so a failure
// can make the next one fail too; the first failure is the one to read.
const surveyOps = `
set -u
export GIT_AUTHOR_NAME=a GIT_AUTHOR_EMAIL=a@b GIT_COMMITTER_NAME=a GIT_COMMITTER_EMAIL=a@b
J="$JJ --config user.name=a --config user.email=a@b"
op() {
  name=$1; shift
  if out=$("$@" 2>&1); then echo "OK $name"; else echo "FAIL $name: $(printf '%s' "$out" | tail -n 3 | tr '\n' ' ')"; fi
}
`

const gitOps = `
cd "$REPO"
op git-commit sh -c 'echo x >> f && git add f && git commit -qm agent'
op git-switch-create git switch -qc feature
op git-commit-on-branch sh -c 'echo y >> f && git commit -qam feature'
op git-tag git tag v1
op git-stash sh -c 'echo z >> f && git stash -q && git stash pop -q && git checkout -q -- f'
op git-rebase sh -c 'git rebase -q main'
op git-fetch git fetch -q origin
op git-push git push -q origin feature
op git-push-set-upstream sh -c 'git push -qu origin feature && test "$(git config branch.feature.merge)" = refs/heads/feature'
op git-set-upstream-to sh -c 'git branch -q tracked && git branch --set-upstream-to=origin/main tracked && test "$(git config branch.tracked.merge)" = refs/heads/main'
op git-remote-add git remote add other "$REMOTE"
op git-config-local git config user.name agent
op git-worktree-add git worktree add -q "$TREES/wt" -b wt
op git-commit-in-worktree sh -c 'cd "$TREES/wt" && echo w >> f && git commit -qam wt'
op git-worktree-remove git worktree remove --force "$TREES/wt"
op git-sparse-checkout git sparse-checkout set --no-cone /f
op git-gc git gc -q
`

const jjOps = `
cd "$JJREPO"
op jj-describe $J describe -m agent
op jj-new $J new
op jj-commit sh -c 'echo x >> f && '"$J"' commit -m second'
op jj-bookmark-create $J bookmark create jj-feature -r @-
op jj-git-fetch $J git fetch
op jj-git-push $J git push --bookmark jj-feature
op jj-git-remote-add $J git remote add other "$REMOTE"
op jj-workspace-add $J workspace add "$TREES/ws"
op jj-commit-in-workspace sh -c 'cd "$TREES/ws" && echo w >> f && '"$J"' commit -m ws'
op jj-workspace-forget $J workspace forget ws
op jj-rebase $J rebase -r @- -d main
op jj-undo $J undo
op jj-squash $J squash -u
`

func TestSurveyOfGitAndJJInTheJail(t *testing.T) {
	jj, err := exec.LookPath("jj")
	if err != nil {
		t.Skip("jj not available")
	}
	if real, err := filepath.EvalSymlinks(jj); err == nil {
		jj = real
	}
	for _, c := range []struct {
		name string
		// mode is how the profile mounts the repositories; the agent's
		// worktrees and workspaces go under the session's writable mount.
		mode string
	}{
		{"writable", "write"},
		{"read-only with the vcs store", "read"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.modules = []string{"vcs-readonly"}
			repos := filepath.Join(e.home, "repos")
			if c.mode == "write" {
				repos = filepath.Join(e.work, "repos")
			}
			remote := filepath.Join(e.work, "remote.git")
			repo := filepath.Join(repos, "git")
			jjRepo := filepath.Join(repos, "jj")
			trees := filepath.Join(e.work, "trees")
			for _, d := range []string{repo, jjRepo, trees} {
				if err := os.MkdirAll(d, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			git(t, e.work, "init", "-q", "--bare", "-b", "main", remote)
			git(t, repo, "init", "-q", "-b", "main")
			if err := os.WriteFile(filepath.Join(repo, "f"), []byte("first\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			git(t, repo, "add", "f")
			git(t, repo, "commit", "-qm", "first")
			git(t, repo, "remote", "add", "origin", remote)
			git(t, repo, "push", "-q", "origin", "main")
			git(t, repo, "fetch", "-q", "origin")

			jjCmd := func(dir string, args ...string) {
				t.Helper()
				cmd := exec.Command(jj, append([]string{"--config", "user.name=t", "--config", "user.email=t@e"}, args...)...)
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "JJ_CONFIG=/dev/null")
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("jj %v: %v\n%s", args, err, out)
				}
			}
			jjCmd(jjRepo, "git", "init", "--colocate")
			if err := os.WriteFile(filepath.Join(jjRepo, "f"), []byte("first\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			jjCmd(jjRepo, "commit", "-m", "first")
			jjCmd(jjRepo, "bookmark", "create", "main", "-r", "@-")
			jjCmd(jjRepo, "git", "remote", "add", "origin", remote)
			jjCmd(jjRepo, "git", "fetch")
			if err := os.Remove(filepath.Join(jjRepo, ".jj", "repo", "git_import_export.lock")); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			configs := map[string][]byte{}
			for _, r := range []string{repo, jjRepo} {
				data, err := os.ReadFile(filepath.Join(r, ".git", "config"))
				if err != nil {
					t.Fatal(err)
				}
				configs[r] = data
			}

			extra := ""
			if c.mode == "read" {
				extra = fmt.Sprintf("[[mounts]]\npath = %q\nmode = \"read\"\n", repos)
			}
			p := e.profile(extra)
			vars := fmt.Sprintf("export JJ=%q REPO=%q JJREPO=%q REMOTE=%q TREES=%q\n", jj, repo, jjRepo, remote, trees)
			ops := gitOps + jjOps
			if c.mode == "read" {
				// The checkout stays read-only, so the agent works in a
				// worktree or workspace of its own.
				ops = strings.ReplaceAll(gitOps, `cd "$REPO"`, `op git-own-worktree git -C "$REPO" worktree add -q "$TREES/main-wt" -b agent; cd "$TREES/main-wt"`) +
					strings.ReplaceAll(jjOps, `cd "$JJREPO"`, `op jj-own-workspace $J --repository "$JJREPO" workspace add "$TREES/main-ws"; cd "$TREES/main-ws"`)
			}
			_, out := e.run(p, vars+surveyOps+ops+"echo survey-done\n", nil)
			if !strings.Contains(out, "survey-done") {
				t.Fatalf("the survey did not finish:\n%s", out)
			}
			var report, unexpected, fixed []string
			for _, line := range strings.Split(out, "\n") {
				switch {
				case strings.HasPrefix(line, "FAIL "):
					report = append(report, line)
					name, _, _ := strings.Cut(strings.TrimPrefix(line, "FAIL "), ":")
					if _, known := knownGaps[name]; !known {
						unexpected = append(unexpected, line)
					}
				case strings.HasPrefix(line, "OK "):
					report = append(report, line)
					if _, known := knownGaps[strings.TrimPrefix(line, "OK ")]; known {
						fixed = append(fixed, strings.TrimPrefix(line, "OK "))
					}
				}
			}
			t.Logf("survey, %s:\n%s", c.name, strings.Join(report, "\n"))
			if len(unexpected) > 0 {
				t.Errorf("operations that fail in the jail:\n%s", strings.Join(unexpected, "\n"))
			}
			if len(fixed) > 0 {
				t.Errorf("known gaps that work now; take them off knownGaps: %v", fixed)
			}
			for r, before := range configs {
				if now, err := os.ReadFile(filepath.Join(r, ".git", "config")); err == nil && string(now) != string(before) {
					t.Logf("%s/.git/config changed during the session:\n%s", r, now)
				}
			}
		})
	}
}
