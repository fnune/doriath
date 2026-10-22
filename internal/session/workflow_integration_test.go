//go:build integration

package session_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/secret"
	"github.com/fnune/doriath/internal/vcstools"
	gittool "github.com/fnune/doriath/internal/vcstools/git"
	jjtool "github.com/fnune/doriath/internal/vcstools/jj"
)

func osKind(p string) string {
	info, err := os.Stat(p)
	switch {
	case err != nil:
		return ""
	case info.IsDir():
		return "dir"
	}
	return "file"
}

// TestAnAgentWorksInARepositorySetUpLikeYours runs the usual agent work on a
// repository set up the way real ones are: cloned, with packed refs, jj
// colocated, your own config signing every commit, a working-copy commit
// that you signed, and jj on the host, which deletes jj's lock file, running
// while the session runs.
func TestAnAgentWorksInARepositorySetUpLikeYours(t *testing.T) {
	jj, err := exec.LookPath("jj")
	if err != nil {
		t.Skip("jj not installed")
	}
	if jj, err = filepath.EvalSymlinks(jj); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	keys := filepath.Join(filepath.Dir(e.home), "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	yours, agents := filepath.Join(keys, "yours"), filepath.Join(keys, "agent")
	for _, k := range []string{yours, agents} {
		if err := os.WriteFile(k, signingKey(t), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	jjConfig := filepath.Join(e.home, ".config", "jj", "config.toml")
	if err := os.MkdirAll(filepath.Dir(jjConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jjConfig, fmt.Appendf(nil, "[user]\nname = \"You\"\nemail = \"you@example.org\"\n\n[signing]\nbehavior = \"own\"\nbackend = \"ssh\"\nkey = %q\n", yours), 0o600); err != nil {
		t.Fatal(err)
	}
	hostJJ := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(jj, args...)
		cmd.Env = append(os.Environ(), "JJ_CONFIG="+jjConfig, "HOME="+e.home, "XDG_CONFIG_HOME="+filepath.Join(e.home, ".config"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("jj %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}

	seed := filepath.Join(e.home, "seed")
	if err := os.MkdirAll(seed, 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, seed, "init", "-q", "-b", "main")
	git(t, seed, "commit", "-q", "--allow-empty", "-m", "first")
	git(t, seed, "branch", "old-feature")
	git(t, seed, "branch", "stale")
	git(t, seed, "tag", "-a", "-m", "v1", "v1")
	remote := filepath.Join(e.home, "remote.git")
	git(t, e.home, "clone", "-q", "--bare", seed, remote)
	repo := filepath.Join(e.home, "repo")
	git(t, e.home, "clone", "-q", remote, repo)
	git(t, repo, "branch", "old-feature", "origin/old-feature")
	git(t, repo, "branch", "stale", "origin/stale")
	git(t, repo, "gc", "-q")
	if _, err := os.Stat(filepath.Join(repo, ".git", "packed-refs")); err != nil {
		t.Fatalf("the clone has no packed refs, so this test checks nothing: %v", err)
	}
	globalIgnore := filepath.Join(e.home, ".config", "git", "ignore")
	if err := os.MkdirAll(filepath.Dir(globalIgnore), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(globalIgnore, []byte(".idea/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, ".idea"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".idea", "workspace.xml"), []byte("<project/>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hostJJ("git", "init", "--colocate", repo)
	hostJJ("-R", repo, "describe", "-m", "your work in progress")
	if !strings.Contains(hostJJ("-R", repo, "log", "-r", "@", "--no-graph", "-T", `if(signature, "signed", "unsigned")`), "signed") {
		t.Fatal("your working-copy commit is not signed, so this test checks nothing")
	}

	desktop := fmt.Appendf(nil, "user.name\nYou\x00user.email\nyou@example.org\x00commit.gpgsign\ntrue\x00gpg.format\nssh\x00user.signingkey\n%s\x00", yours)
	e.vcs = []vcstools.Tool{gittool.New(desktop, map[string][]byte{"core.excludesfile": []byte(".idea/\n")}), jjtool.New(e.home, osKind)}
	e.secrets["agent-key"] = secret.Backend{File: agents}
	p := e.profile(fmt.Sprintf(`
[[mounts]]
path = %q
mode = "read"

[vcs]
store = true

[signing]
key = "agent-key"
`, repo))

	code, out := e.run(p, fmt.Sprintf(`
R=%[1]s
J="%[2]s --config user.name=You --config user.email=you@example.org"
$J -R $R file list | grep -q .idea && echo "FAIL jj tracks what your global ignore covers"
[ -z "$(git -C $R status --porcelain --ignored=no -- .idea)" ] || echo "FAIL git shows what your global ignore covers"
echo /tmp/elsewhere > $R/.git/commondir
for i in $(seq 100); do [ -e $R/.git/commondir ] || break; sleep 0.01; done
[ -e $R/.git/commondir ] && echo "FAIL the commondir stayed while the session ran"
$J -R $R describe -m "the agent describes your work" || echo "FAIL describe"
$J -R $R new -m "the agent's work" || echo "FAIL new"
$J -R $R bookmark create agent -r @- || echo "FAIL bookmark create"
$J -R $R bookmark delete stale || echo "FAIL delete a packed bookmark"
git -C $R branch -D old-feature || echo "FAIL delete a packed branch"
git -C $R tag -d v1 || echo "FAIL delete a packed tag"
[ "$($J -R $R log -r agent --no-graph -T 'if(signature, "signed", "unsigned")')" = signed ] || echo "FAIL the agent's commit is unsigned"
echo done
`, repo, jj), func() {
		time.Sleep(time.Second)
		for end := time.Now().Add(2 * time.Second); time.Now().Before(end); {
			cmd := exec.Command(jj, "-R", repo, "log", "-r", "@", "--no-graph", "-T", "change_id")
			cmd.Env = append(os.Environ(), "JJ_CONFIG="+jjConfig, "HOME="+e.home, "XDG_CONFIG_HOME="+filepath.Join(e.home, ".config"))
			_ = cmd.Run()
			time.Sleep(20 * time.Millisecond)
		}
	})
	if code != 0 || !strings.Contains(out, "done") || strings.Contains(out, "FAIL") || strings.Contains(out, "Failed to take lock") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if _, err := os.Lstat(filepath.Join(repo, ".git", "commondir")); err == nil {
		t.Error("a commondir in the store sends libgit2, and so nix, to a broken worktree")
	}
	if !strings.Contains(hostJJ("-R", repo, "bookmark", "list"), "agent") {
		t.Error("the agent's bookmark is missing on the host")
	}
}
