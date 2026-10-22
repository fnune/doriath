package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func modulesCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	p, err := paths()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = cmdModules(p, loader(p), args, strings.NewReader(""), &out)
	return out.String(), err
}

func TestModulesListShowsOriginAndSummary(t *testing.T) {
	p := testPaths(t)
	if err := os.MkdirAll(p.Modules(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.Modules(), "go.toml"), []byte("# My Go. With more.\n[egress]\nallow = [\"proxy.golang.org\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.Modules(), "team.toml"), []byte("# The team's hosts.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := modulesCmd(t, "list")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"base", "built in", "go", "yours, in place of the built-in", "My Go.", "team", "The team's hosts."} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "With more.") {
		t.Errorf("the summary is more than the first sentence:\n%s", out)
	}
}

func TestModulesShowPrintsTheFileOrAPath(t *testing.T) {
	p := testPaths(t)
	out, err := modulesCmd(t, "show", "github")
	if err != nil || !strings.Contains(out, "api.github.com") {
		t.Fatalf("show github = %v\n%s", err, out)
	}
	path, err := modulesCmd(t, "show", "github", "--path")
	if err != nil {
		t.Fatal(err)
	}
	path = strings.TrimSpace(path)
	if !strings.HasPrefix(path, p.Cache) {
		t.Errorf("a built-in's path %q is not under the cache %q", path, p.Cache)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != out {
		t.Errorf("the copy at %s differs from show: %v", path, err)
	}
	if again, err := modulesCmd(t, "show", "github", "--path"); err != nil || strings.TrimSpace(again) != path {
		t.Errorf("a second --path = %q, %v", again, err)
	}
	if _, err := modulesCmd(t, "show", "missing"); err == nil || !strings.Contains(err.Error(), "doriath modules list") {
		t.Errorf("a missing module = %v", err)
	}
}

func TestModulesEditCopiesTheBuiltinAndChecksIt(t *testing.T) {
	p := testPaths(t)
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "true")
	out, err := modulesCmd(t, "edit", "go")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	copied := filepath.Join(p.Modules(), "go.toml")
	if data, err := os.ReadFile(copied); err != nil || !strings.Contains(string(data), "proxy.golang.org") {
		t.Fatalf("the built-in was not copied: %v", err)
	}
	t.Setenv("EDITOR", `sed -i 's/^\[egress\]/[nonsense]/'`)
	if _, err := modulesCmd(t, "edit", "go"); err == nil {
		t.Fatal("an edit that breaks the module must fail")
	}
	if _, err := modulesCmd(t, "edit", "missing"); err == nil {
		t.Fatal("editing a module that exists nowhere must fail")
	}
}
