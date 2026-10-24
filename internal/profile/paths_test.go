package profile

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

const guardModule = `
[paths]
refuse = ["~/.ssh"]

[[paths.warn]]
path = "~/.local/bin"
reason = "Your shells run programs from it."

[[paths.hold]]
path = "{repository}/.envrc"
reason = "direnv runs it."
missing = "hold"
`

func guardedLoader(profiles fstest.MapFS) *Loader {
	l := loader(profiles, fstest.MapFS{
		"guard.toml": file(guardModule),
		"tools.toml": file("[[paths.warn]]\npath = \"{repository}/default.nix\"\nreason = \"use nix reads it.\"\n"),
	})
	l.Builtins = []string{"guard"}
	return l
}

func TestBuiltinModulesLoadIntoEveryProfile(t *testing.T) {
	p, err := guardedLoader(fstest.MapFS{"app.toml": file("")}).Load("app")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.PathRules.Refuse, "/home/u/.ssh") || len(p.PathRules.Warn) != 1 || len(p.PathRules.Hold) != 1 {
		t.Errorf("rules = %+v", p.PathRules)
	}
	if slices.Contains(p.Modules, "guard") {
		t.Errorf("a built-in module is in every profile, so the list of its modules leaves it out: %v", p.Modules)
	}
}

func TestPathListsCombineAcrossLayersAsAUnion(t *testing.T) {
	l := guardedLoader(fstest.MapFS{"app.toml": file("modules = [\"tools\", \"guard\"]\n\n[[paths.hold]]\npath = \"{repository}/.envrc\"\nreason = \"mine\"\nmissing = \"skip\"\n")})
	p, err := l.Load("app")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.PathRules.Warn) != 2 {
		t.Errorf("warnings = %+v", p.PathRules.Warn)
	}
	if len(p.PathRules.Hold) != 1 || p.PathRules.Hold[0].Missing != MissingHold || p.PathRules.Hold[0].Reason != "direnv runs it." {
		t.Errorf("a later layer must not weaken a hold: %+v", p.PathRules.Hold)
	}
}

func TestPathListsStayOutOfTheGrants(t *testing.T) {
	profiles := fstest.MapFS{"app.toml": file("[egress]\nallow = [\"example.com\"]\n")}
	plain, err := loader(profiles, fstest.MapFS{}).Load("app")
	if err != nil {
		t.Fatal(err)
	}
	guarded, err := guardedLoader(profiles).Load("app")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := plain.Grants()
	after, _ := guarded.Grants()
	if !slices.Equal(before, after) {
		t.Errorf("a built-in list asks you again: %v, then %v", before, after)
	}
}

func TestARepositoryProfileCannotMountARefusedPath(t *testing.T) {
	l := guardedLoader(fstest.MapFS{})
	l = withRepository(l, fstest.MapFS{"dev.toml": file("[[mounts]]\npath = \"~/.ssh/keys\"\n")})
	if _, err := l.Load("repo:dev"); err == nil || !strings.Contains(err.Error(), "a repository profile cannot show") {
		t.Errorf("err = %v", err)
	}
}

func TestAHeldPathIsReadOnlyWhereAMountShowsIt(t *testing.T) {
	rules := PathRules{Hold: []PathHold{{Path: "{repository}/.envrc", Reason: "r", Missing: MissingHold}, {Path: "{repository}/secret/.envrc", Reason: "r", Missing: MissingHold}}}
	writable := &Profile{Mounts: []Mount{{Path: "{repository}", Mode: ModeWrite}, {Path: "{repository}/secret", Mode: ModeHide}, {Path: "{repository}/.envrc", Mode: ModeWrite}}, PathRules: rules}
	got := resolve(t, writable, inRepo)
	if mode(got, "/home/u/src/app/.envrc") != ModeRead {
		t.Errorf("a profile cannot make a held file writable: %+v", got)
	}
	if mode(got, "/home/u/src/app/secret/.envrc") != "" {
		t.Errorf("a hold must not show a file in a hidden folder: %+v", got)
	}
	if got := resolve(t, &Profile{PathRules: rules}, Start{Current: "/home/u/src/app/pkg", Repository: "/home/u/src/app"}); mode(got, "/home/u/src/app/.envrc") != "" {
		t.Errorf("a hold must not show a file that no mount shows: %+v", got)
	}
	r, err := writable.Resolve(Start{Current: "/tmp/x"}, "/home/u")
	if err != nil || len(r.PathRules.Hold) != 0 {
		t.Errorf("outside a repository, entries with %s go: %+v, %v", Repository, r.PathRules, err)
	}
}

func TestAWarningCoversThePathItsParentsAndWhatIsInside(t *testing.T) {
	rules := PathRules{
		Warn: []PathWarning{{Path: "/home/u/.local/bin", Reason: "bin"}, {Path: "/tmp", Reason: "sockets", Read: true}},
		Hold: []PathHold{{Path: "/home/u/src/app/.husky", Reason: "hooks"}},
	}
	for _, c := range []struct {
		path string
		read bool
		want string
	}{
		{"/home/u/.local/bin", false, "bin"},
		{"/home/u/.local/bin/git", false, "bin"},
		{"/home/u/.local", false, "bin"},
		{"/home/u/.local/share", false, ""},
		{"/home/u/.local/bin", true, ""},
		{"/tmp", true, "sockets"},
		{"/home/u/src/app", false, "hooks"},
		{"/home/u/src/app", true, ""},
	} {
		w, ok := rules.Warning(c.path, c.read)
		if ok != (c.want != "") || w.Reason != c.want {
			t.Errorf("Warning(%s, read %v) = %+v, %v, want %q", c.path, c.read, w, ok, c.want)
		}
	}
}

func TestPathListEntriesNeedACleanPathAndAReason(t *testing.T) {
	for _, body := range []string{
		"[paths]\nrefuse = [\"~/.ssh/\"]\n",
		"[paths]\nrefuse = [\"~/a/../.ssh\"]\n",
		"[paths]\nrefuse = [\".ssh\"]\n",
		"[paths]\nrefuse = [\"{current}/.envrc\"]\n",
		"[[paths.warn]]\npath = \"~/bin\"\n",
		"[[paths.hold]]\npath = \"{repository}/.envrc\"\nreason = \"r\"\n",
		"[[paths.hold]]\npath = \"{repository}/.envrc\"\nmissing = \"hold\"\n",
	} {
		if _, err := loader(fstest.MapFS{"p.toml": file(body)}, fstest.MapFS{}).Load("p"); err == nil {
			t.Errorf("%q loads", body)
		}
	}
}
