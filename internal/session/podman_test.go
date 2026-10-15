package session

import (
	"os"
	"path/filepath"
	"testing"
)

func TestContainerBindsResolveLinksInTheJailsCache(t *testing.T) {
	root := t.TempDir()
	backing := filepath.Join(root, "agent", "home", ".cache", "go-build")
	own := filepath.Join(root, "home", ".cache", "go-build")
	secret := filepath.Join(root, "run", "podman-raw")
	for _, d := range []string{backing, own, secret} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(secret, filepath.Join(backing, "raw")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(backing, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	j := jailPaths{caches: map[string]string{own: backing}}
	for p, want := range map[string]string{
		filepath.Join(own, "raw"):  secret,
		filepath.Join(own, "data"): filepath.Join(own, "data"),
		own:                        own,
	} {
		got, err := j.EvalSymlinks(p)
		if err != nil || got != want {
			t.Errorf("%s resolves to %q (%v), want %s", p, got, err, want)
		}
	}
}
