package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		Config:  "/home/u/.config/doriath",
		State:   "/home/u/.local/state/doriath",
		Cache:   "/c/doriath",
		Runtime: "/run/user/1000/doriath",
	}
	if p != want {
		t.Fatalf("got %+v", p)
	}
	if _, err := DefaultPaths(env(map[string]string{"HOME": "/home/u"})); err == nil {
		t.Fatal("a missing XDG_RUNTIME_DIR must be an error")
	}
	p, err = DefaultPaths(env(map[string]string{"HOME": "/home/u", "XDG_RUNTIME_DIR": "/r", "DORIATH_CONFIG_DIR": "/nix/store/x"}))
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

	write("[secrets.x]\nfile = \"~/token\"\n")
	if _, err := LoadUser(path); err == nil || !strings.Contains(err.Error(), "unknown keys") {
		t.Fatalf("err = %v, want unknown keys", err)
	}
}

func TestDefaultPathsRejectsRelativeDirectories(t *testing.T) {
	for name, vars := range map[string]map[string]string{
		"no home":              {"XDG_RUNTIME_DIR": "/r"},
		"relative home":        {"HOME": "home/u", "XDG_RUNTIME_DIR": "/r"},
		"relative config dir":  {"HOME": "/home/u", "XDG_RUNTIME_DIR": "/r", "DORIATH_CONFIG_DIR": "conf"},
		"relative runtime dir": {"HOME": "/home/u", "XDG_RUNTIME_DIR": "r"},
	} {
		if _, err := DefaultPaths(env(vars)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	p, err := DefaultPaths(env(map[string]string{"HOME": "/home/u", "XDG_RUNTIME_DIR": "/r", "XDG_CONFIG_HOME": "rel"}))
	if err != nil || p.Config != "/home/u/.config/doriath" {
		t.Fatalf("a relative XDG_CONFIG_HOME falls back to the default: %+v, %v", p, err)
	}
}

func TestHostWait(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	for content, want := range map[string]time.Duration{
		"":                                   2 * time.Minute,
		"[approvals]\ndesktop = false\n":     0,
		"[approvals]\nhost_wait = \"30s\"\n": 30 * time.Second,
		"[approvals]\ndesktop = false\nhost_wait = \"1h\"\n": time.Hour,
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		u, err := LoadUser(path)
		if err != nil || u.Approvals.DefaultHostWait() != want {
			t.Errorf("%q: wait %v, %v; want %v", content, u.Approvals.DefaultHostWait(), err, want)
		}
	}
	for _, bad := range []string{"soon", "-1s", "2h"} {
		if err := os.WriteFile(path, []byte("[approvals]\nhost_wait = \""+bad+"\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadUser(path); err == nil || !strings.Contains(err.Error(), "want a duration from 0s to 1h, such as 2m") {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
}
