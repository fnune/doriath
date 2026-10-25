package profile_test

import (
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/fnune/doriath/internal/modules"
	"github.com/fnune/doriath/internal/profile"
)

func repositoryProfile(t *testing.T, body string) *profile.Profile {
	t.Helper()
	l := &profile.Loader{
		Profiles: fstest.MapFS{"p.toml": {Data: []byte(body)}},
		Modules:  []fs.FS{modules.FS},
		Home:     "/home/u",
		Builtins: modules.Builtins,
	}
	p, err := l.Load("p")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mountAt(p *profile.Profile, path string) (profile.Mount, bool) {
	i := slices.IndexFunc(p.Mounts, func(m profile.Mount) bool { return m.Path == path })
	if i < 0 {
		return profile.Mount{}, false
	}
	return p.Mounts[i], true
}

func TestAModuleAppliesInAnotherRepositoryWithTheProfilesGuards(t *testing.T) {
	p := repositoryProfile(t, `modules = ["vcs-readwrite", "claude"]

[[mounts]]
path = "{repository}/web/dist"
mode = "write"

[[mounts]]
path = "{repository}/secrets"
mode = "hide"
`)
	ext, err := p.ForRepository("vcs-readwrite", "/home/u/other", "/home/u", nil)
	if err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]profile.Mode{
		"/home/u/other":                       profile.ModeWrite,
		"/home/u/other/mise.toml":             profile.ModeRead,
		"/home/u/other/.claude/settings.json": profile.ModeRead,
		"/home/u/other/secrets":               profile.ModeHide,
	} {
		if m, ok := mountAt(ext, path); !ok || m.Mode != mode {
			t.Errorf("mount %s = %+v, %v, want mode %s", path, m, ok, mode)
		}
	}
	for _, path := range []string{"/home/u/other/web/dist", "/home/u/other/.claude/worktrees", "/home/u/.config/jj", "/home/u/.claude/settings.json"} {
		if m, ok := mountAt(ext, path); ok {
			t.Errorf("mount %s = %+v: the module does not grant it, or the session has it already", path, m)
		}
	}
	if !slices.ContainsFunc(ext.PathRules.Hold, func(h profile.PathHold) bool { return h.Path == "/home/u/other/.envrc" }) {
		t.Errorf("the built-in holds do not reach the other repository: %+v", ext.PathRules.Hold)
	}
	if slices.ContainsFunc(ext.PathRules.Warn, func(w profile.PathWarning) bool { return !strings.HasPrefix(w.Path, "/home/u/other") }) {
		t.Errorf("warnings outside the repository came along: %+v", ext.PathRules.Warn)
	}
	if !ext.VCSStore {
		t.Error("vcs-readwrite opens the store")
	}
	if ext.GitEdits["config"] == nil {
		t.Error("the safe edits of .git/config do not come along")
	}
}

func TestAModuleGrantsOnlyItsOwnPathsInAnotherRepository(t *testing.T) {
	p := repositoryProfile(t, `modules = ["vcs-readwrite", "claude"]`)
	ext, err := p.ForRepository("claude", "/home/u/other", "/home/u", nil)
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := mountAt(ext, "/home/u/other/.claude/worktrees"); !ok || m.Mode != profile.ModeWrite {
		t.Errorf("worktrees = %+v, %v", m, ok)
	}
	if m, ok := mountAt(ext, "/home/u/other"); !ok || m.Mode != profile.ModeRead {
		t.Errorf("the repository = %+v, %v, want read-only", m, ok)
	}
	if ext.VCSStore {
		t.Error("claude does not open the store")
	}
}

func TestVCSReadonlyOpensTheStoreOfAnotherRepositoryOnly(t *testing.T) {
	p := repositoryProfile(t, `modules = ["vcs-readonly"]`)
	ext, err := p.ForRepository("vcs-readonly", "/home/u/other", "/home/u", nil)
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := mountAt(ext, "/home/u/other"); !ok || m.Mode != profile.ModeRead {
		t.Errorf("the repository = %+v, %v, want read-only", m, ok)
	}
	if !ext.VCSStore {
		t.Error("vcs-readonly opens the store")
	}
	ext, err = p.ForRepository("vcs-readwrite", "/home/u/other", "/home/u", nil)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := mountAt(ext, "/home/u/other"); m.Mode != profile.ModeRead {
		t.Errorf("vcs-readwrite under vcs-readonly makes the checkout %s, want read-only as in the session", m.Mode)
	}
}

func TestOnlyModulesOfTheProfileThatGrantInARepositoryApply(t *testing.T) {
	p := repositoryProfile(t, `modules = ["vcs-readwrite", "go"]`)
	for module, refusal := range map[string]string{
		"claude": `does not use module "claude". It uses: vcs-readwrite, go`,
		"go":     `module "go" grants nothing in a repository`,
	} {
		if _, err := p.ForRepository(module, "/home/u/other", "/home/u", nil); err == nil || !strings.Contains(err.Error(), refusal) {
			t.Errorf("%s: %v, want %q", module, err, refusal)
		}
	}
	if got := p.RepositoryModules(); !slices.Equal(got, []string{"vcs-readwrite"}) {
		t.Errorf("RepositoryModules = %v", got)
	}
}
