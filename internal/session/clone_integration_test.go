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

func gitAt(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.org", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.org")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git -C %s %v: %v\n%s", dir, args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func newRepo(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	gitAt(t, dir, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitAt(t, dir, "add", "README")
	gitAt(t, dir, "commit", "-q", "-m", "first")
}

func cloneMount(path string) string {
	return fmt.Sprintf("\n[[mounts]]\npath = %q\nmode = \"clone\"\n", path)
}

func landed(t *testing.T, repo string) []string {
	t.Helper()
	return strings.Fields(gitAt(t, repo, "for-each-ref", "--format=%(refname)", "refs/girdle/"))
}

func (e *env) clonesLeft(profileName string) []string {
	e.t.Helper()
	left, err := filepath.Glob(filepath.Join(e.paths.AgentCache(profileName), "clones", "*"))
	if err != nil {
		e.t.Fatal(err)
	}
	return left
}

const agentCommits = `git switch -q -c feature
echo agent > README
git -c user.name=Agent -c user.email=a@example.org commit -q -am "agent change" || echo "FAIL commit"
`

func requireLandedFeature(t *testing.T, repo, out string) {
	t.Helper()
	refs := landed(t, repo)
	var feature string
	for _, r := range refs {
		if strings.HasSuffix(r, "/feature") {
			feature = r
		}
	}
	if feature == "" {
		t.Fatalf("no landed feature branch in %v\noutput:\n%s", refs, out)
	}
	if msg := gitAt(t, repo, "log", "-1", "--format=%s", feature); msg != "agent change" {
		t.Errorf("landed commit = %q", msg)
	}
}

func TestCloneOfJJColocatedRepository(t *testing.T) {
	if lookPath("git") == "" || lookPath("jj") == "" {
		t.Skip("git or jj not installed")
	}
	e := newEnv(t)
	repo := filepath.Join(e.home, "repo")
	newRepo(t, repo)
	jjConfig := filepath.Join(filepath.Dir(e.home), "jj.toml")
	if err := os.WriteFile(jjConfig, []byte("user.name = \"t\"\nuser.email = \"t@example.org\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runJJ := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("jj", append([]string{"--no-pager", "--color=never"}, args...)...)
		cmd.Env = append(os.Environ(), "JJ_CONFIG="+jjConfig, "GIT_CONFIG_GLOBAL=/dev/null")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("jj %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	jj := func(args ...string) string {
		t.Helper()
		return runJJ(append([]string{"--repository", repo}, args...)...)
	}
	runJJ("git", "init", "--colocate", repo)
	jj("describe", "-m", "the person's work in progress")
	opsBefore := jj("op", "log", "--no-graph", "-T", `id ++ "\n"`)
	workingCopy := jj("log", "--no-graph", "-r", "@", "-T", "commit_id")

	p := e.profile(cloneMount(repo))
	code, out := e.run(p, fmt.Sprintf("cd %q\ntest -e .jj && echo \"FAIL the clone carries the person's jj state\"\n%secho done\n", repo, agentCommits), nil)
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "done") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	requireLandedFeature(t, repo, out)

	jj("status")
	if got := jj("log", "--no-graph", "-r", "conflicts() | divergent()", "-T", `commit_id ++ "\n"`); got != "" {
		t.Errorf("jj sees conflicts or divergent changes after landing:\n%s", got)
	}
	if got := jj("log", "--no-graph", "-r", "@", "-T", "commit_id"); got != workingCopy {
		t.Errorf("the jj working-copy commit changed from %s to %s", workingCopy, got)
	}
	if got := jj("bookmark", "list", "--all-remotes"); strings.Contains(got, "feature") {
		t.Errorf("jj imported a landed ref as a bookmark:\n%s", got)
	}
	if opsAfter := jj("op", "log", "--no-graph", "-T", `id ++ "\n"`); !strings.HasSuffix(opsAfter, opsBefore) {
		t.Errorf("jj's operation log lost history:\nbefore:\n%s\nafter:\n%s", opsBefore, opsAfter)
	}
	if got, _ := os.ReadFile(filepath.Join(repo, "README")); string(got) != "original\n" {
		t.Errorf("the person's working copy changed: %q", got)
	}
}

func TestCloneOfRepositoryWithSubmodule(t *testing.T) {
	if lookPath("git") == "" {
		t.Skip("git not installed")
	}
	e := newEnv(t)
	lib := filepath.Join(e.home, "lib")
	newRepo(t, lib)
	repo := filepath.Join(e.home, "repo")
	newRepo(t, repo)
	gitAt(t, repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", lib, "lib")
	gitAt(t, repo, "commit", "-q", "-m", "add lib")

	// A shared clone of a superproject does not carry .git/modules, so the
	// submodule is not populated: the agent sees the gitlink, not lib's files.
	p := e.profile(cloneMount(repo))
	code, out := e.run(p, fmt.Sprintf(`cd %q
test -f .gitmodules || echo "FAIL the clone lacks .gitmodules"
test -e lib/README && echo "FAIL the clone unexpectedly populated the submodule"
echo x >> .git/config 2>/dev/null && echo "FAIL clone config writable"
touch .git/hooks/pre-commit 2>/dev/null && echo "FAIL clone hooks writable"
%secho done
`, repo, agentCommits), nil)
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "done") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	requireLandedFeature(t, repo, out)
	if got, _ := os.ReadFile(filepath.Join(repo, "lib", "README")); string(got) != "original\n" {
		t.Errorf("the person's submodule checkout changed: %q", got)
	}
	if left := e.clonesLeft(p.Name); len(left) != 0 {
		t.Errorf("a clone whose work all landed must be removed: %v", left)
	}
}

func TestCloneOfWorktree(t *testing.T) {
	if lookPath("git") == "" {
		t.Skip("git not installed")
	}
	e := newEnv(t)
	repo := filepath.Join(e.home, "repo")
	newRepo(t, repo)
	worktree := filepath.Join(e.home, "repo-side")
	gitAt(t, repo, "worktree", "add", "-q", "-b", "side", worktree)
	if err := os.WriteFile(filepath.Join(worktree, "README"), []byte("side\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitAt(t, worktree, "commit", "-q", "-am", "side work")
	sideHead := gitAt(t, worktree, "rev-parse", "HEAD")
	mainHead := gitAt(t, repo, "rev-parse", "HEAD")

	p := e.profile(cloneMount(worktree))
	code, out := e.run(p, fmt.Sprintf(`cd %q
test "$(cat README)" = side || echo "FAIL the clone is not at the worktree's HEAD"
echo x >> .git/config 2>/dev/null && echo "FAIL clone config writable"
%secho done
`, worktree, agentCommits), nil)
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "done") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	requireLandedFeature(t, worktree, out)
	if fromMain := landed(t, repo); len(fromMain) == 0 {
		t.Error("the landed refs must be in the repository that the worktree belongs to")
	}
	if got := gitAt(t, worktree, "rev-parse", "HEAD"); got != sideHead {
		t.Error("the worktree's HEAD moved")
	}
	if got := gitAt(t, repo, "rev-parse", "HEAD"); got != mainHead {
		t.Error("the main checkout's HEAD moved")
	}
	if got, _ := os.ReadFile(filepath.Join(worktree, "README")); string(got) != "side\n" {
		t.Errorf("the worktree's files changed: %q", got)
	}
}

func TestCloneWithoutAgentCommitsLeavesNothing(t *testing.T) {
	if lookPath("git") == "" {
		t.Skip("git not installed")
	}
	e := newEnv(t)
	repo := filepath.Join(e.home, "repo")
	newRepo(t, repo)
	gitAt(t, repo, "switch", "-q", "-c", "wip")
	gitAt(t, repo, "commit", "-q", "--allow-empty", "-m", "ahead of main")

	p := e.profile(fmt.Sprintf("\n[[mounts]]\npath = %q\nmode = \"clone\"\nref = \"main\"\n", repo))
	code, out := e.run(p, fmt.Sprintf("cd %q && git status --short && git log --oneline >/dev/null && echo done\n", repo), nil)
	if code != 0 || !strings.Contains(out, "done") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if refs := landed(t, repo); len(refs) != 0 {
		t.Errorf("a session without commits must leave no refs: %v", refs)
	}
	if left := e.clonesLeft(p.Name); len(left) != 0 {
		t.Errorf("a clone without work must be removed: %v", left)
	}
	for _, phrase := range []string{"new commit", "--clone-from", "could not"} {
		if strings.Contains(out, phrase) {
			t.Errorf("a session without work has nothing to report, found %q:\n%s", phrase, out)
		}
	}
}

func TestUncommittedWorkResumesAndLands(t *testing.T) {
	if lookPath("git") == "" {
		t.Skip("git not installed")
	}
	e := newEnv(t)
	repo := filepath.Join(e.home, "repo")
	newRepo(t, repo)
	p := e.profile(cloneMount(repo))

	code, out := e.run(p, fmt.Sprintf("cd %q && echo draft > README && echo new > notes\n", repo), nil)
	if code != 0 {
		t.Fatalf("first session: %d\n%s", code, out)
	}
	first := e.lastID
	if !strings.Contains(out, "--clone-from "+first) {
		t.Fatalf("a clone with uncommitted changes must be kept and named for --clone-from:\n%s", out)
	}
	if left := e.clonesLeft(p.Name); len(left) == 0 {
		t.Fatal("the clone with uncommitted changes was removed")
	}
	if refs := landed(t, repo); len(refs) != 0 {
		t.Errorf("uncommitted work must not land refs: %v", refs)
	}

	e.cloneFrom = first
	code, out = e.run(p, fmt.Sprintf(`cd %q
test "$(cat README)" = draft || echo "FAIL tracked change lost"
test "$(cat notes)" = new || echo "FAIL untracked file lost"
git switch -q -c feature
git add notes
git -c user.name=Agent -c user.email=a@example.org commit -q -am "agent change" || echo "FAIL commit"
echo done
`, repo), nil)
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "done") {
		t.Fatalf("resumed session: %d\n%s", code, out)
	}
	requireLandedFeature(t, repo, out)
	if left := e.clonesLeft(p.Name); len(left) != 0 {
		t.Errorf("a resumed clone whose work all landed must be removed: %v", left)
	}
	if got, _ := os.ReadFile(filepath.Join(repo, "README")); string(got) != "original\n" {
		t.Errorf("the source checkout changed: %q", got)
	}
}
