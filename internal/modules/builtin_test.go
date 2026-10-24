package modules

import (
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/fnune/doriath/internal/profile"
)

func builtinLoader(profiles fstest.MapFS) *profile.Loader {
	return &profile.Loader{Profiles: profiles, Modules: []fs.FS{FS}, Home: "/home/u", Builtins: Builtins}
}

func TestEveryProfileRefusesYourKeysAndLogins(t *testing.T) {
	p, err := builtinLoader(fstest.MapFS{"empty.toml": {Data: []byte("")}}).Load("empty")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/home/u/.ssh", "/home/u/.gnupg", "/home/u/.password-store", "/home/u/.gitconfig", "/home/u/.config/jj"} {
		if !slices.Contains(p.PathRules.Refuse, path) {
			t.Errorf("%s is not refused: %v", path, p.PathRules.Refuse)
		}
	}
}

func TestAUserModuleCannotTakeTheNameOfABuiltinModule(t *testing.T) {
	l := builtinLoader(fstest.MapFS{"empty.toml": {Data: []byte("")}})
	l.Modules = []fs.FS{fstest.MapFS{Builtins[0] + ".toml": {Data: []byte("")}}, FS}
	if _, err := l.Load("empty"); err == nil {
		t.Error("a user module replaced a built-in module")
	}
}

func TestARequestForAPathThatYourMachineRunsOnItsOwnWarns(t *testing.T) {
	p, err := builtinLoader(fstest.MapFS{"empty.toml": {Data: []byte("")}}).Load("empty")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		path string
		read bool
		want bool
	}{
		{"/home/u/.local/bin", false, true},
		{"/home/u/.local", false, true},
		{"/home/u/.config/systemd/user", false, true},
		{"/home/u/.zshrc", false, true},
		{"/home/u/.local/bin", true, false},
		{"/tmp", false, true},
		{"/tmp", true, true},
		{"/home/u/src/app", false, false},
	} {
		if w, ok := p.PathRules.Warning(c.path, c.read); ok != c.want {
			t.Errorf("%s, read %v: %+v, %v", c.path, c.read, w, ok)
		}
	}
}

func TestAProfileThatYouAllowedBeforeTheBuiltinModulesStartsWithoutAQuestion(t *testing.T) {
	before := fstest.MapFS{}
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := fs.ReadFile(FS, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		before[e.Name()] = &fstest.MapFile{Data: data}
	}
	old, err := os.ReadFile("testdata/vcs-readwrite-before.toml")
	if err != nil {
		t.Fatal(err)
	}
	before["vcs-readwrite.toml"] = &fstest.MapFile{Data: old}
	profiles := fstest.MapFS{"app.toml": {Data: []byte("modules = [\"vcs-readwrite\", \"claude\", \"nix\"]\n")}}
	approved, err := (&profile.Loader{Profiles: profiles, Modules: []fs.FS{before}, Home: "/home/u"}).Load("app")
	if err != nil {
		t.Fatal(err)
	}
	now, err := builtinLoader(profiles).Load("app")
	if err != nil {
		t.Fatal(err)
	}
	was, _ := approved.Grants()
	is, _ := now.Grants()
	if added, removed := profile.Added(was, is), profile.Removed(was, is); len(added) > 0 || len(removed) > 0 {
		t.Errorf("the upgrade asks again: added %v, removed %v", added, removed)
	}
}

func TestAWritableRepositoryHoldsTheFilesThatYourMachineRuns(t *testing.T) {
	p, err := builtinLoader(fstest.MapFS{"app.toml": {Data: []byte("modules = [\"vcs-readwrite\"]\n")}}).Load("app")
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Resolve(profile.Start{Current: "/home/u/src/app", Repository: "/home/u/src/app"}, "/home/u")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"lefthook-local.yml", ".config/lefthook.toml", ".lefthook", ".husky", ".pre-commit-config.yaml", ".envrc", ".env", "shell.nix", ".direnv", ".nvim.lua", ".devcontainer"} {
		path := "/home/u/src/app/" + name
		i := slices.IndexFunc(r.Mounts, func(m profile.Mount) bool { return m.Path == path })
		if i < 0 || r.Mounts[i].Mode != profile.ModeRead || r.Mounts[i].Missing != profile.MissingSkip {
			t.Errorf("%s is not read-only, or gets a placeholder where it is missing: %+v", name, r.Mounts)
		}
		if j := slices.IndexFunc(r.PathRules.Hold, func(h profile.PathHold) bool { return h.Path == path }); j < 0 || r.PathRules.Hold[j].Missing != profile.MissingMove {
			t.Errorf("%s is not moved out where it is missing", name)
		}
	}
	if !r.PathRules.HoldsFolder("/home/u/src/app/.vscode") {
		t.Error(".vscode must be held with an empty folder")
	}
	if slices.ContainsFunc(r.Mounts, func(m profile.Mount) bool { return strings.HasSuffix(m.Path, "/rr-cache") }) {
		t.Error("a held rr-cache turns rerere on")
	}
}
