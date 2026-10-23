package main

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/clipboard"
	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/notify"
	"github.com/fnune/doriath/internal/secret"
)

func TestRunExitStatus(t *testing.T) {
	p := testPaths(t)
	writeProfile(t, p, "app", `modules = ["base"]`)
	for _, tc := range []struct {
		args []string
		want int
	}{
		{nil, 2},
		{[]string{"no-such-command"}, 2},
		{[]string{"help"}, 0},
		{[]string{"version"}, 0},
		{[]string{"profiles", "show", "app"}, 0},
		{[]string{"profiles", "show", "missing"}, 1},
		{[]string{"run", "--", "true"}, 2},
		{[]string{"run", "--profile", "app"}, 2},
		{[]string{"run", "--no-such-flag"}, 2},
		{[]string{"run", "--profile", "app", "--current", "/no/such/dir", "--", "true"}, 2},
		{[]string{"run", "--profile", "missing", "--", "true"}, 1},
		{[]string{"exec", "--no-such-flag"}, 2},
		{[]string{"exec"}, 1},
		{[]string{"doctor", "--no-such-flag"}, 2},
	} {
		if code := run(tc.args); code != tc.want {
			t.Errorf("doriath %q exits %d, want %d", tc.args, code, tc.want)
		}
	}
}

type desktopNotifier struct{}

func (desktopNotifier) Notify(context.Context, approval.Request, func(approval.Decision)) (func(), error) {
	return func() {}, nil
}

func TestHostWaitHoldsRequestsOnlyWhereSomeoneSeesThem(t *testing.T) {
	five := 5 * time.Second
	for name, tc := range map[string]struct {
		approvals config.Approvals
		notifier  approval.Notifier
		want      time.Duration
	}{
		"no notifications":             {config.Approvals{Desktop: true}, notify.None{}, 0},
		"no notifications, configured": {config.Approvals{HostWait: &five}, notify.None{}, five},
		"desktop notifications":        {config.Approvals{Desktop: true}, desktopNotifier{}, 2 * time.Minute},
		"desktop, configured":          {config.Approvals{Desktop: true, HostWait: &five}, desktopNotifier{}, five},
	} {
		if got := hostWait(tc.approvals, tc.notifier); got != tc.want {
			t.Errorf("%s: host wait = %v, want %v", name, got, tc.want)
		}
	}
}

func TestLimitedBufferKeepsTheStartOfLongOutput(t *testing.T) {
	var l limitedBuffer
	start := bytes.Repeat([]byte("a"), 4000)
	for _, chunk := range [][]byte{start, bytes.Repeat([]byte("b"), 200), bytes.Repeat([]byte("c"), 5000)} {
		if n, err := l.Write(chunk); n != len(chunk) || err != nil {
			t.Fatalf("write = %d, %v; the command must not see a short write", n, err)
		}
	}
	want := slices.Concat(start, bytes.Repeat([]byte("b"), 96))
	if !bytes.Equal(l.b, want) {
		t.Errorf("kept %d bytes ending in %q", len(l.b), l.b[len(l.b)-4:])
	}
}

func TestTheGitFrontAsksForAbsoluteWorktreePaths(t *testing.T) {
	got := absoluteWorktrees([]string{"-c", "worktree.useRelativePaths=true", "worktree", "add", "worktree.useRelativePaths=true"})
	want := []string{"-c", "worktree.useRelativePaths=false", "worktree", "add", "worktree.useRelativePaths=true"}
	if !slices.Equal(got, want) {
		t.Errorf("args = %q, want %q: only the setting jj passes with -c changes", got, want)
	}
}

func TestHostClipboardNeedsAWaylandSessionAndWlPaste(t *testing.T) {
	env := map[string]string{"WAYLAND_DISPLAY": "wayland-1", "XDG_RUNTIME_DIR": "/run/user/1000"}
	getenv := func(k string) string { return env[k] }
	src, ok := hostClipboard(getenv, "/bin/wl-paste").(clipboard.WlPaste)
	if !ok || src.Bin != "/bin/wl-paste" || !slices.Equal(src.Env, []string{"WAYLAND_DISPLAY=wayland-1", "XDG_RUNTIME_DIR=/run/user/1000"}) {
		t.Errorf("source = %+v", src)
	}
	if hostClipboard(getenv, "") != nil {
		t.Error("without wl-paste there is no clipboard")
	}
	if hostClipboard(func(string) string { return "" }, "/bin/wl-paste") != nil {
		t.Error("outside a Wayland session there is no clipboard")
	}
}

func TestRepositoryProfilesComeFromTheRootOfTheRepository(t *testing.T) {
	repo := t.TempDir()
	sub := filepath.Join(repo, "pkg", "deep")
	for _, d := range []string{filepath.Join(repo, ".git"), filepath.Join(repo, ".doriath"), sub} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, ".doriath", "dev.toml"), []byte("[egress]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, modules := repositoryProfiles(sub)
	if root != repo || modules == nil {
		t.Fatal("no repository profiles from a folder inside the repository")
	}
	if _, err := fs.ReadFile(modules, "dev.toml"); err != nil {
		t.Fatal(err)
	}
	if _, none := repositoryProfiles(""); none != nil {
		t.Error("repository profiles without a folder")
	}
	if _, none := repositoryProfiles(t.TempDir()); none != nil {
		t.Error("repository profiles without a repository")
	}
}

func TestARepositoryProfileCannotLinkToAFileOutsideTheFolder(t *testing.T) {
	repo := t.TempDir()
	for _, d := range []string{filepath.Join(repo, ".git"), filepath.Join(repo, ".doriath")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(t.TempDir(), "secret.toml")
	if err := os.WriteFile(outside, []byte("[egress]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(repo, ".doriath", "dev.toml")); err != nil {
		t.Fatal(err)
	}
	_, profiles := repositoryProfiles(repo)
	if _, err := fs.ReadFile(profiles, "dev.toml"); err == nil {
		t.Fatal("read a file outside .doriath through a symlink")
	}
}

func TestAPasswordPromptIsPrecededByTheProfilesOwnCommand(t *testing.T) {
	got := terminalNotice(secret.Command{Secret: "github", Argv: []string{"sh", "-c", "bw unlock --raw"}})
	if !strings.Contains(got, "secret github") || !strings.HasSuffix(got, "\nsh -c 'bw unlock --raw'") {
		t.Errorf("notice = %q", got)
	}
}

func TestDoriathsNextMessageStartsOnItsOwnLine(t *testing.T) {
	for out, want := range map[string]string{"You are not logged in.": "You are not logged in.\n", "done\n": "done\n", "": ""} {
		var b bytes.Buffer
		l := &lineCloser{w: &b}
		_, _ = l.Write([]byte(out))
		l.closeLine()
		if b.String() != want {
			t.Errorf("%q = %q, want %q", out, b.String(), want)
		}
	}
}
