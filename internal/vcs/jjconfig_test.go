package vcs

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// securedJJRepo makes a colocated jj repository, with jj's secure configs in a
// directory of the test's own.
func securedJJRepo(t *testing.T) (jjRepoDir string, tools Tools) {
	t.Helper()
	jj, err := exec.LookPath("jj")
	if err != nil {
		t.Skip("jj not installed")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JJ_CONFIG", "")
	repo := filepath.Join(t.TempDir(), "repo")
	cmd := exec.Command(jj, "git", "init", "--colocate", repo)
	cmd.Dir = t.TempDir()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("jj git init: %v\n%s", err, out)
	}
	return filepath.Join(repo, ".jj", "repo"), Tools{JJ: jj}
}

// secureDir checks that dir is the secure config that the repository's
// config-id names.
func secureDir(t *testing.T, jjRepo, dir string) {
	t.Helper()
	id, err := os.ReadFile(filepath.Join(jjRepo, "config-id"))
	if err != nil {
		t.Fatalf("no config-id: %v", err)
	}
	if filepath.Base(dir) != string(id) {
		t.Errorf("secure config %s, config-id %s", dir, id)
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Errorf("the secure config is not there: %v", err)
	}
}

func TestJJSecureConfigGivesARepositoryItsID(t *testing.T) {
	jjRepo, tools := securedJJRepo(t)
	dir, err := JJSecureConfig(context.Background(), tools, jjRepo)
	if err != nil {
		t.Fatal(err)
	}
	secureDir(t, jjRepo, dir)
	again, err := JJSecureConfig(context.Background(), tools, jjRepo)
	if err != nil || again != dir {
		t.Errorf("a second call found %s, %v, want %s", again, err, dir)
	}
}

// An empty config.toml is the placeholder of an earlier session: jj would
// migrate it, and replace it with a link into your config.
func TestJJSecureConfigRemovesAnEmptyLegacyConfigFirst(t *testing.T) {
	jjRepo, tools := securedJJRepo(t)
	legacy := filepath.Join(jjRepo, "config.toml")
	if err := os.WriteFile(legacy, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	dir, err := JJSecureConfig(context.Background(), tools, jjRepo)
	if err != nil {
		t.Fatal(err)
	}
	secureDir(t, jjRepo, dir)
	if _, err := os.Lstat(legacy); !os.IsNotExist(err) {
		t.Errorf("the empty legacy config stays, perhaps as a link: %v", err)
	}
}

func TestJJSecureConfigLeavesYourLegacyConfigToJJ(t *testing.T) {
	jjRepo, tools := securedJJRepo(t)
	legacy := filepath.Join(jjRepo, "config.toml")
	if err := os.WriteFile(legacy, []byte("[ui]\ncolor = \"never\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir, err := JJSecureConfig(context.Background(), tools, jjRepo)
	if err != nil || dir != "" {
		t.Fatalf("JJSecureConfig = %q, %v", dir, err)
	}
	if info, err := os.Lstat(legacy); err != nil || !info.Mode().IsRegular() {
		t.Errorf("your legacy config changed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(jjRepo, "config-id")); !os.IsNotExist(err) {
		t.Errorf("doriath made a config-id beside your legacy config: %v", err)
	}
}

func TestJJSecureConfigWithoutJJDoesNothing(t *testing.T) {
	if dir, err := JJSecureConfig(context.Background(), Tools{}, t.TempDir()); err != nil || dir != "" {
		t.Errorf("JJSecureConfig = %q, %v", dir, err)
	}
}
