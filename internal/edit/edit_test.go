package edit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/fnune/doriath/internal/profile"
)

var vcsRules = []profile.SafeChange{
	{Key: "branch.*.remote", Value: "*"},
	{Key: "branch.*.merge", Value: "refs/heads/**"},
	{Key: "extensions.relativeworktrees", Value: "true"},
	{Key: "core.repositoryformatversion", Value: "1"},
}

const current = `[core]
	repositoryformatversion = 0
	bare = false
[remote "origin"]
	url = git@github.com:fnune/doriath.git
`

func changes(t *testing.T, new string) []Change {
	t.Helper()
	c, err := Changes(context.Background(), "git", profile.FormatGitConfig, []byte(current), []byte(new))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func allSafe(c []Change) bool {
	for _, x := range c {
		if !Safe(x, vcsRules) {
			return false
		}
	}
	return len(c) > 0
}

func TestUpstreamTrackingIsSafe(t *testing.T) {
	c := changes(t, current+"[branch \"ada/topic\"]\n\tremote = origin\n\tmerge = refs/heads/ada/topic\n")
	if len(c) != 2 || !allSafe(c) {
		t.Errorf("changes = %+v", c)
	}
}

func TestARemoteGitWouldReadFromAFileIsNotSafe(t *testing.T) {
	if c := changes(t, current+"[branch \"main\"]\n\tremote = evil\n"); allSafe(c) {
		t.Errorf("a remote without a url passes as safe: %+v", c)
	}
	if c := changes(t, current+"[branch \"main\"]\n\tremote = .\n"); !allSafe(c) {
		t.Errorf("tracking a local branch must stay safe: %+v", c)
	}
}

func TestCommentsAndLayoutAreNoChange(t *testing.T) {
	if c := changes(t, "# a comment\n"+strings.ReplaceAll(current, "\t", "    ")); len(c) != 0 {
		t.Errorf("changes = %+v", c)
	}
}

func TestSettingsThatRunCommandsAreNeverSafe(t *testing.T) {
	for _, extra := range []string{
		"[core]\n\tfsmonitor = /tmp/evil\n",
		"[core]\n\thooksPath = /tmp/hooks\n",
		"[include]\n\tpath = /tmp/more\n",
		"[branch \"main\"]\n\tremote = https://evil.example/repo.git\n",
		"[branch \"main\"]\n\tmerge = refs/remotes/origin/main\n",
		"[remote \"origin\"]\n\turl = https://evil.example/repo.git\n",
	} {
		if c := changes(t, current+extra); allSafe(c) {
			t.Errorf("%q passes as safe: %+v", extra, c)
		}
	}
}

func TestAnIncludeIsNotFollowed(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "more")
	if err := os.WriteFile(outside, []byte("[core]\n\tfsmonitor = /tmp/evil\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := changes(t, current+"[include]\n\tpath = "+outside+"\n")
	for _, x := range c {
		if x.Key == "core.fsmonitor" {
			t.Fatal("the included file was read")
		}
	}
}

func TestApplyWritesOnlyTheChangedSettingsInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(current), 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	new := "# the agent's comment\n" + current + "[branch \"topic\"]\n\tremote = origin\n"
	c := changes(t, new)
	if err := Apply(context.Background(), "git", path, profile.FormatGitConfig, []byte(new), c); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "remote = origin") || strings.Contains(string(data), "the agent's comment") {
		t.Errorf("config:\n%s", data)
	}
	after, _ := os.Stat(path)
	if before.Sys().(*syscall.Stat_t).Ino != after.Sys().(*syscall.Stat_t).Ino {
		t.Error("the file was replaced, so a mount of it would show the old content")
	}
}

func TestATextEditIsAlwaysShownAndNeverSafe(t *testing.T) {
	c, err := Changes(context.Background(), "git", profile.FormatText, []byte("use flake\n"), []byte("use flake\ndotenv\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != 1 || Safe(c[0], vcsRules) || Describe(c, nil) != "+ dotenv\n" {
		t.Errorf("changes = %+v\n%s", c, Describe(c, nil))
	}
}
