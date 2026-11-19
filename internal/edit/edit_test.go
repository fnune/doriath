package edit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

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
	checked, err := Check(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), "git", checked, profile.FormatGitConfig, []byte(new), c); err != nil {
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

func TestAnEditNeverWritesThroughASymlinkSwappedInAfterTheCheck(t *testing.T) {
	ctx := context.Background()
	for attempt := range 40 {
		dir := t.TempDir()
		victim := filepath.Join(dir, "victim")
		path := filepath.Join(dir, "config")
		swap := filepath.Join(dir, "swap")
		payload := "[x]\n\ty = ;echo escaped\n"
		for file, content := range map[string]string{victim: "original\n", path: payload} {
			if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(victim, swap); err != nil {
			t.Fatal(err)
		}
		var stop atomic.Bool
		done := make(chan struct{})
		go func() {
			defer close(done)
			for !stop.Load() {
				_ = unix.Renameat2(unix.AT_FDCWD, path, unix.AT_FDCWD, swap, unix.RENAME_EXCHANGE)
			}
		}()
		checked, err := Check(path)
		if err == nil {
			next := checked.Content
			next = append(append([]byte{}, next...), []byte("[branch \"b\"]\n\tmerge = refs/heads/b\n")...)
			c, cerr := Changes(ctx, "git", profile.FormatGitConfig, checked.Content, next)
			if cerr != nil {
				t.Fatal(cerr)
			}
			_ = Apply(ctx, "git", checked, profile.FormatGitConfig, next, c)
		}
		stop.Store(true)
		<-done
		if data, _ := os.ReadFile(victim); string(data) != "original\n" {
			t.Fatalf("attempt %d: the file behind the symlink holds:\n%s", attempt, data)
		}
	}
}

func TestAnEditFailsWhenAParentDirectoryBecomesASymlink(t *testing.T) {
	root := t.TempDir()
	store := filepath.Join(root, "store")
	elsewhere := filepath.Join(root, "elsewhere")
	for _, dir := range []string{store, elsewhere} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "config"), []byte(current), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	checked, err := Check(filepath.Join(store, "config"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(store, store+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, store); err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), "git", checked, profile.FormatText, []byte("changed\n"), nil); err == nil {
		t.Error("Apply wrote through a symlinked parent")
	}
	if data, _ := os.ReadFile(filepath.Join(elsewhere, "config")); string(data) != current {
		t.Errorf("the file behind the symlink holds:\n%s", data)
	}
}

func TestAnEditFailsWhenAnotherFileTakesThePlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte(current), 0o644); err != nil {
		t.Fatal(err)
	}
	checked, err := Check(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("other\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), "git", checked, profile.FormatText, []byte("changed\n"), nil); err == nil {
		t.Error("Apply wrote to a file that doriath did not check")
	}
}

func TestACheckRefusesASymlinkAndANonRegularFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(link); err == nil {
		t.Error("Check followed a symlink")
	}
	if _, err := Check(dir); err == nil {
		t.Error("Check accepted a directory")
	}
}
