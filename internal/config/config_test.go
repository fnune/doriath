package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaultPaths(t *testing.T) {
	p, err := DefaultPaths(env(map[string]string{"HOME": "/home/u", "XDG_RUNTIME_DIR": "/run/user/1000", "XDG_CACHE_HOME": "/c"}))
	if err != nil {
		t.Fatal(err)
	}
	want := Paths{
		Home:    "/home/u",
		Config:  "/home/u/.config/girdle",
		State:   "/home/u/.local/state/girdle",
		Cache:   "/c/girdle",
		Runtime: "/run/user/1000/girdle",
	}
	if p != want {
		t.Fatalf("got %+v", p)
	}
	if _, err := DefaultPaths(env(map[string]string{"HOME": "/home/u"})); err == nil {
		t.Fatal("a missing XDG_RUNTIME_DIR must be an error")
	}
	p, err = DefaultPaths(env(map[string]string{"HOME": "/home/u", "XDG_RUNTIME_DIR": "/r", "GIRDLE_CONFIG_DIR": "/nix/store/x"}))
	if err != nil || p.Config != "/nix/store/x" {
		t.Fatalf("override: %+v, %v", p, err)
	}
}

func TestLoadUser(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	u, err := LoadUser(filepath.Join(dir, "missing.toml"), "/home/u")
	if err != nil || !u.Approvals.Desktop || len(u.Secrets) != 0 {
		t.Fatalf("missing file: %+v, %v", u, err)
	}

	write(`
[secrets.github-project]
file = "~/.config/girdle/secrets/github"

[secrets.agent-signing]
command = ["rbw", "get", "agent-signing"]

[approvals]
desktop = false
`)
	u, err = LoadUser(path, "/home/u")
	if err != nil {
		t.Fatal(err)
	}
	if u.Secrets["github-project"].File != "/home/u/.config/girdle/secrets/github" {
		t.Errorf("file = %q", u.Secrets["github-project"].File)
	}
	if got := u.Secrets["agent-signing"].Command; len(got) != 3 || got[0] != "rbw" {
		t.Errorf("command = %v", got)
	}
	if u.Approvals.Desktop {
		t.Error("desktop should be false")
	}

	for body, want := range map[string]string{
		"[secrets.x]\nfile = \"a\"\ncommand = [\"b\"]": "not both",
		"[secrets.x]\n":               "set file or command",
		"[secrets.x]\nfile = \"rel\"": "must be absolute",
		"colour = \"blue\"":           "unknown keys: colour",
	} {
		write(body)
		if _, err := LoadUser(path, "/home/u"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", body, err, want)
		}
	}
}
