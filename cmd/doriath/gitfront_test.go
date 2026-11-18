package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/approval"
)

func frontRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	for k, v := range map[string]string{"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e"} {
		t.Setenv(k, v)
	}
	dir := t.TempDir()
	remote, work := filepath.Join(dir, "remote.git"), filepath.Join(dir, "work")
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q", "--bare", "-b", "main", remote)
	run("init", "-q", "-b", "main", work)
	run("-C", work, "commit", "-q", "--allow-empty", "-m", "first")
	run("-C", work, "remote", "add", "origin", remote)
	run("-C", work, "push", "-q", "origin", "main")
	run("-C", work, "switch", "-qc", "feature")
	if err := os.Chmod(filepath.Join(work, ".git"), 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(work, ".git"), 0o755) })
	t.Chdir(work)
	return work
}

func gitConfig(t *testing.T, repo, key string) string {
	t.Helper()
	out, _ := exec.Command("git", "-C", repo, "config", "--get", key).Output()
	return strings.TrimSpace(string(out))
}

func TestTheGitFrontRecordsTheUpstreamOfAQuietPush(t *testing.T) {
	repo := frontRepo(t)
	b := startBroker(t)
	b.set(approval.Decision{Verdict: approval.VerdictAllow}, nil)
	if code := cmdGitFront([]string{"push", "-qu", "origin", "feature"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if gitConfig(t, repo, "branch.feature.remote") != "origin" || gitConfig(t, repo, "branch.feature.merge") != "refs/heads/feature" {
		t.Errorf("the upstream is not recorded: %+v", b.edits)
	}
	if len(b.edits) != 1 || b.edits[0].Path != filepath.Join(repo, ".git", "config") {
		t.Errorf("edits = %+v", b.edits)
	}
}

func TestTheGitFrontRecordsAnUpstreamYouSetWithBranch(t *testing.T) {
	repo := frontRepo(t)
	b := startBroker(t)
	b.set(approval.Decision{Verdict: approval.VerdictAllow}, nil)
	cmdGitFront([]string{"branch", "--set-upstream-to=origin/main", "feature"})
	if gitConfig(t, repo, "branch.feature.remote") != "origin" || gitConfig(t, repo, "branch.feature.merge") != "refs/heads/main" {
		t.Errorf("the upstream is not recorded: %+v", b.edits)
	}
}

func TestTheGitFrontAddsARemoteOnceYouAllowIt(t *testing.T) {
	repo := frontRepo(t)
	b := startBroker(t)
	b.set(approval.Decision{Verdict: approval.VerdictDeny}, nil)
	if code := cmdGitFront([]string{"remote", "add", "other", "https://example.com/other.git"}); code == 0 {
		t.Error("a refused remote add succeeded")
	}
	if gitConfig(t, repo, "remote.other.url") != "" {
		t.Error("a refused remote is in the config")
	}
	b.set(approval.Decision{Verdict: approval.VerdictAllow}, nil)
	if code := cmdGitFront([]string{"remote", "add", "other", "https://example.com/other.git"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if gitConfig(t, repo, "remote.other.url") != "https://example.com/other.git" || gitConfig(t, repo, "remote.other.fetch") != "+refs/heads/*:refs/remotes/other/*" {
		t.Errorf("the remote is not in the config: %+v", b.edits)
	}
}

func TestTheGitFrontLeavesOtherFailuresAlone(t *testing.T) {
	frontRepo(t)
	b := startBroker(t)
	b.set(approval.Decision{Verdict: approval.VerdictAllow}, nil)
	if code := cmdGitFront([]string{"push", "-q", "nowhere", "feature"}); code == 0 {
		t.Error("a push to a missing remote succeeded")
	}
	if len(b.edits) != 0 {
		t.Errorf("edits = %+v", b.edits)
	}
}

func TestParseGitFollowsDashC(t *testing.T) {
	t.Chdir(t.TempDir())
	wd, _ := os.Getwd()
	inv := parseGit([]string{"-c", "a=b", "-C", "repo", "-C", "sub", "--no-pager", "push", "-u"})
	if inv.dir != filepath.Join(wd, "repo", "sub") || inv.command != "push" || !slices.Equal(inv.args, []string{"-u"}) {
		t.Errorf("invocation = %+v", inv)
	}
}

func TestSplitUpstreamPrefersTheLongestRemote(t *testing.T) {
	for upstream, want := range map[string][2]string{
		"origin/main":        {"origin", "main"},
		"origin/team/main":   {"origin/team", "main"},
		"main":               {".", "main"},
		"upstream/feature/x": {"upstream", "feature/x"},
	} {
		remote, branch := splitUpstream(upstream, []string{"origin", "origin/team", "upstream"})
		if remote != want[0] || branch != want[1] {
			t.Errorf("%s = %s %s, want %v", upstream, remote, branch, want)
		}
	}
}
