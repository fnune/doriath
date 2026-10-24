package modules

import (
	"io/fs"
	"slices"
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
