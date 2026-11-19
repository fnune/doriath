package session

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/fnune/doriath/internal/profile"
)

func repoWithHooksPath(t *testing.T, value string) string {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "app")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "-C", repo, "init", "-q")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	if value != "" {
		cmd := exec.Command("git", "-C", repo, "config", "core.hooksPath", value)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git config: %v\n%s", err, out)
		}
	}
	return repo
}

func holdsOf(p *profile.Profile, path string) (readOnly, folder bool) {
	for _, m := range p.Mounts {
		if m.Path == path && m.Mode == profile.ModeRead && m.Missing == profile.MissingHold {
			readOnly = true
		}
	}
	return readOnly, p.PathRules.HoldsFolder(path)
}

func writeMount(repo string) *profile.Profile {
	return &profile.Profile{Mounts: []profile.Mount{{Path: repo, Mode: profile.ModeWrite}}}
}

func TestAHooksFolderInsideAWritableCheckoutIsHeldReadOnly(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	repo := repoWithHooksPath(t, ".githooks")
	got := withHookFolders(writeMount(repo), osHost{}, gitHooksPath("git"))
	if readOnly, folder := holdsOf(got, filepath.Join(repo, ".githooks")); !readOnly || !folder {
		t.Errorf("the folder core.hooksPath names is not held: %+v", got.Mounts)
	}
}

func TestTheHooksPathOfYourGlobalConfigIsHeldToo(t *testing.T) {
	repo := repoWithHooksPath(t, "")
	read := func(file string) string {
		if file == "" {
			return "tools/hooks"
		}
		return ""
	}
	got := withHookFolders(writeMount(repo), osHost{}, read)
	if readOnly, _ := holdsOf(got, filepath.Join(repo, "tools", "hooks")); !readOnly {
		t.Errorf("the folder of the global core.hooksPath is not held: %+v", got.Mounts)
	}
}

func TestAHooksFolderOutsideTheWritableMountsAndInsideTheStoreNeedNoHold(t *testing.T) {
	for name, value := range map[string]string{"outside": "/opt/hooks", "inside the store": ".git/hooks"} {
		t.Run(name, func(t *testing.T) {
			repo := repoWithHooksPath(t, value)
			got := withHookFolders(writeMount(repo), osHost{}, gitHooksPath("git"))
			if len(got.Mounts) != 1 {
				t.Errorf("mounts = %+v", got.Mounts)
			}
		})
	}
}

func TestAReadOnlyCheckoutNeedsNoHooksHold(t *testing.T) {
	repo := repoWithHooksPath(t, ".githooks")
	p := &profile.Profile{Mounts: []profile.Mount{{Path: repo, Mode: profile.ModeRead}}}
	if got := withHookFolders(p, osHost{}, gitHooksPath("git")); !slices.Equal(got.Mounts, p.Mounts) {
		t.Errorf("mounts = %+v", got.Mounts)
	}
}

func TestARelativeHooksPathIsHeldInLinkedWorktreesToo(t *testing.T) {
	repo := repoWithHooksPath(t, ".githooks")
	for _, args := range [][]string{{"commit", "-q", "--allow-empty", "-m", "first"}, {"worktree", "add", "-q", "--detach", "wt"}} {
		cmd := exec.Command("git", append([]string{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.com"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	linked := filepath.Join(repo, "wt")
	got := withHookFolders(writeMount(repo), osHost{}, gitHooksPath("git"))
	if readOnly, folder := holdsOf(got, filepath.Join(linked, ".githooks")); !readOnly || !folder {
		t.Errorf("the hooks folder of the linked worktree is not held: %+v", got.Mounts)
	}
}
