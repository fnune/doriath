package modules

import (
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

type entry struct {
	Path    string `toml:"path"`
	Reason  string `toml:"reason"`
	Missing string `toml:"missing"`
	Folder  bool   `toml:"folder"`
	Mode    string `toml:"mode"`
}

type shipped struct {
	Paths struct {
		Refuse []string `toml:"refuse"`
		Warn   []entry  `toml:"warn"`
		Hold   []entry  `toml:"hold"`
	} `toml:"paths"`
	Mounts []entry `toml:"mounts"`
	Caches []entry `toml:"caches"`
}

func readModule(t *testing.T, name string) (shipped, map[string]any) {
	t.Helper()
	data, err := fs.ReadFile(FS, name+".toml")
	if err != nil {
		t.Fatal(err)
	}
	var m shipped
	var raw map[string]any
	if _, err := toml.Decode(string(data), &raw); err != nil {
		t.Fatal(err)
	}
	if _, err := toml.Decode(string(data), &m); err != nil {
		t.Fatal(err)
	}
	return m, raw
}

const home = "/home/u"

func expand(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		return home + path[1:]
	}
	return path
}

func within(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

func touches(a, b string) bool {
	a, b = expand(a), expand(b)
	return within(a, b) || within(b, a)
}

func TestABuiltinModuleOnlyRefusesWarnsOrHolds(t *testing.T) {
	for _, name := range Builtins {
		_, raw := readModule(t, name)
		for key, value := range raw {
			if key == "description" {
				continue
			}
			paths, ok := value.(map[string]any)
			if key != "paths" || !ok {
				t.Errorf("%s: %s gives the jail something; a built-in module can only refuse, warn or hold", name, key)
				continue
			}
			for list := range paths {
				if !slices.Contains([]string{"refuse", "warn", "hold"}, list) {
					t.Errorf("%s: paths.%s is not a refuse, warn or hold list", name, list)
				}
			}
		}
	}
}

func TestABuiltinEntryNamesOneCleanPathBelowTheHomeOrTheRepository(t *testing.T) {
	for _, name := range Builtins {
		m, _ := readModule(t, name)
		paths := slices.Clone(m.Paths.Refuse)
		for _, e := range append(slices.Clone(m.Paths.Warn), m.Paths.Hold...) {
			paths = append(paths, e.Path)
		}
		for _, p := range paths {
			switch {
			case slices.Contains(strings.Split(p, "/"), ".."), strings.HasSuffix(p, "/"):
				t.Errorf("%s: %q has .. or a trailing slash", name, p)
			case !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "~/") && !strings.HasPrefix(p, "{repository}/"):
				t.Errorf("%s: %q starts at neither /, ~ nor {repository}", name, p)
			case within(home, expand(p)):
				t.Errorf("%s: %q covers the home, so its warning would show on every request", name, p)
			}
		}
	}
}

func TestNoTwoBuiltinEntriesNameOnePath(t *testing.T) {
	seen := map[string]string{}
	add := func(name, list, path string) {
		if prev, ok := seen[path]; ok {
			t.Errorf("%s is in %s and in %s %s", path, prev, name, list)
		}
		seen[path] = name + " " + list
	}
	for _, name := range Builtins {
		m, _ := readModule(t, name)
		for _, p := range m.Paths.Refuse {
			add(name, "refuse", p)
		}
		for _, e := range m.Paths.Warn {
			add(name, "warn", e.Path)
		}
		for _, e := range m.Paths.Hold {
			add(name, "hold", e.Path)
		}
	}
}

func TestEveryBuiltinWarningHasAReason(t *testing.T) {
	for _, name := range Builtins {
		m, _ := readModule(t, name)
		for _, e := range append(slices.Clone(m.Paths.Warn), m.Paths.Hold...) {
			if strings.TrimSpace(e.Reason) == "" {
				t.Errorf("%s: %s has no reason, which is what the request shows", name, e.Path)
			}
		}
	}
}

func TestABuiltinRepositoryEntryCannotStayWhereItWasMissing(t *testing.T) {
	for _, name := range Builtins {
		m, _ := readModule(t, name)
		for _, p := range append(slices.Clone(m.Paths.Refuse), pathsOf(m.Paths.Warn)...) {
			if strings.HasPrefix(p, "{repository}") {
				t.Errorf("%s: %s is in the repository, so hold it", name, p)
			}
		}
		for _, e := range m.Paths.Hold {
			switch {
			case e.Missing == "move":
			case e.Missing == "hold" && (e.Folder || strings.HasSuffix(e.Path, ".json")):
			case e.Missing == "hold":
				t.Errorf("%s: %s gets an empty file where it is missing, which a tool on your machine would read; use missing = \"move\"", name, e.Path)
			default:
				t.Errorf("%s: %s has missing = %q, so the agent can create it where it is missing", name, e.Path, e.Missing)
			}
		}
	}
}

func pathsOf(entries []entry) []string {
	var out []string
	for _, e := range entries {
		out = append(out, e.Path)
	}
	return out
}

func TestNoShippedModuleWritesWhereABuiltinModuleRefusesOrWarns(t *testing.T) {
	var guarded, held []string
	for _, name := range Builtins {
		m, _ := readModule(t, name)
		guarded = append(append(guarded, m.Paths.Refuse...), pathsOf(m.Paths.Warn)...)
		held = append(held, pathsOf(m.Paths.Hold)...)
	}
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".toml")
		if !ok || slices.Contains(Builtins, name) {
			continue
		}
		m, _ := readModule(t, name)
		var writable []string
		for _, mount := range m.Mounts {
			if mount.Mode == "write" {
				writable = append(writable, mount.Path)
			}
		}
		for _, c := range m.Caches {
			writable = append(writable, c.Path)
		}
		for _, w := range writable {
			for _, g := range guarded {
				if touches(w, g) {
					t.Errorf("%s makes %s writable, which touches %s", name, w, g)
				}
			}
			for _, h := range held {
				if within(expand(w), expand(h)) {
					t.Errorf("%s makes %s writable, which a built-in module holds", name, w)
				}
			}
		}
	}
}
