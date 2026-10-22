package profile

import (
	"errors"
	iofs "io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

const minimalProfile = `description = "test"
modules = []
`

func write(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func link(t *testing.T, target, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

func dirLoader(dir string) *Loader {
	return &Loader{Profiles: os.DirFS(dir), Modules: []iofs.FS{fstest.MapFS{}}, Home: "/home/u"}
}

func TestProfilesInFoldersAndLinkedFolders(t *testing.T) {
	root := t.TempDir()
	profiles := filepath.Join(root, "profiles")
	clone := filepath.Join(root, "doriath-profiles")
	write(t, filepath.Join(profiles, "public.toml"), minimalProfile)
	write(t, filepath.Join(profiles, "work", "team.toml"), minimalProfile)
	write(t, filepath.Join(clone, "acme-service.toml"), minimalProfile)
	write(t, filepath.Join(clone, "README.md"), "# Profiles")
	write(t, filepath.Join(clone, "nested", "deeper", "tools.toml"), minimalProfile)
	link(t, clone, filepath.Join(profiles, "private"))
	write(t, filepath.Join(root, "store", "from-nix.toml"), minimalProfile)
	link(t, filepath.Join(root, "store", "from-nix.toml"), filepath.Join(profiles, "from-nix.toml"))

	l := dirLoader(profiles)
	names, err := l.Names()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"from-nix", "public", "acme-service", "team", "tools"}
	if !slices.Equal(names, want) {
		t.Fatalf("names = %q, want %q", names, want)
	}
	for _, name := range want {
		p, err := l.Load(name)
		if err != nil {
			t.Fatalf("load %s: %v", name, err)
		}
		if p.Name != name {
			t.Errorf("load %s: name %q", name, p.Name)
		}
	}
}

func TestProfilesSkipHiddenFolders(t *testing.T) {
	profiles := t.TempDir()
	write(t, filepath.Join(profiles, "a.toml"), minimalProfile)
	write(t, filepath.Join(profiles, "private", ".git", "a.toml"), "not a profile")
	write(t, filepath.Join(profiles, "private", ".jj", "repo", "b.toml"), "not a profile")
	write(t, filepath.Join(profiles, ".c.toml"), "not a profile")

	l := dirLoader(profiles)
	names, err := l.Names()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names, []string{"a"}) {
		t.Fatalf("names = %q", names)
	}
	if _, err := l.Load("b"); !errors.Is(err, iofs.ErrNotExist) {
		t.Fatalf("a file in .jj must not be a profile: %v", err)
	}
}

func TestTwoFilesWithOneNameAreAnError(t *testing.T) {
	profiles := t.TempDir()
	write(t, filepath.Join(profiles, "app.toml"), minimalProfile)
	write(t, filepath.Join(profiles, "private", "app.toml"), minimalProfile)
	write(t, filepath.Join(profiles, "other.toml"), minimalProfile)

	l := dirLoader(profiles)
	for what, err := range map[string]error{
		"names":      second(l.Names()),
		"load":       second(l.Load("app")),
		"load other": second(l.Load("other")),
	} {
		if err == nil || !strings.Contains(err.Error(), `two files define profile "app"`) || !strings.Contains(err.Error(), "private/app.toml") {
			t.Errorf("%s: %v", what, err)
		}
	}
}

func TestALinkBackToAParentEndsTheWalk(t *testing.T) {
	profiles := t.TempDir()
	write(t, filepath.Join(profiles, "a.toml"), minimalProfile)
	link(t, profiles, filepath.Join(profiles, "loop"))

	_, err := dirLoader(profiles).Names()
	if err == nil || !strings.Contains(err.Error(), "loop links back to a folder above it") {
		t.Fatalf("got %v", err)
	}
}

func TestABrokenLinkNamesItself(t *testing.T) {
	profiles := t.TempDir()
	write(t, filepath.Join(profiles, "a.toml"), minimalProfile)
	link(t, filepath.Join(profiles, "gone"), filepath.Join(profiles, "private"))

	_, err := dirLoader(profiles).Load("a")
	if err == nil || !strings.Contains(err.Error(), "private") || !errors.Is(err, iofs.ErrNotExist) {
		t.Fatalf("got %v", err)
	}
}

func TestProfilesNestAtMostEightFoldersDeep(t *testing.T) {
	profiles := t.TempDir()
	write(t, filepath.Join(profiles, "a", "b", "c", "d", "e", "f", "g", "seven.toml"), minimalProfile)
	if _, err := dirLoader(profiles).Load("seven"); err != nil {
		t.Fatalf("seven folders deep: %v", err)
	}
	write(t, filepath.Join(profiles, "a", "b", "c", "d", "e", "f", "g", "h", "eight.toml"), minimalProfile)
	if _, err := dirLoader(profiles).Names(); err == nil || !strings.Contains(err.Error(), "more than 8 folders deep") {
		t.Fatalf("eight folders deep: %v", err)
	}
}

func TestNoProfilesFolder(t *testing.T) {
	l := dirLoader(filepath.Join(t.TempDir(), "missing"))
	names, err := l.Names()
	if err != nil || len(names) != 0 {
		t.Fatalf("names %q, %v", names, err)
	}
	if _, err := l.Load("app"); err == nil || !strings.Contains(err.Error(), `read profile "app"`) || !errors.Is(err, iofs.ErrNotExist) {
		t.Fatalf("got %v", err)
	}
}

func TestAProfileInAFolderKeepsTheNameCheck(t *testing.T) {
	profiles := t.TempDir()
	write(t, filepath.Join(profiles, "private", "app.toml"), "name = \"other\"\n"+minimalProfile)
	if _, err := dirLoader(profiles).Load("app"); err == nil || !strings.Contains(err.Error(), `name field says "other"`) {
		t.Fatalf("got %v", err)
	}
}

func second[T any](_ T, err error) error { return err }
