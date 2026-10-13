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

	u, err := LoadUser(filepath.Join(dir, "missing.toml"))
	if err != nil || !u.Approvals.Desktop {
		t.Fatalf("missing file: %+v, %v", u, err)
	}

	write("[approvals]\ndesktop = false\n")
	u, err = LoadUser(path)
	if err != nil || u.Approvals.Desktop {
		t.Fatalf("desktop should be false: %+v, %v", u, err)
	}

	// Secrets belong to profiles, so config.toml has no place for them.
	write("[secrets.x]\nfile = \"~/token\"\n")
	if _, err := LoadUser(path); err == nil || !strings.Contains(err.Error(), "unknown keys") {
		t.Fatalf("err = %v, want unknown keys", err)
	}
}
