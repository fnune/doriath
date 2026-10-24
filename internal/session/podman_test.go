package session

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/fnune/doriath/internal/containers"
	"github.com/fnune/doriath/internal/profile"
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

func TestContainersCannotWriteTheControlFilesOfNestedAndSubmoduleStores(t *testing.T) {
	repo := t.TempDir()
	nested := filepath.Join(repo, "vendored", ".git", "config")
	submodule := filepath.Join(repo, ".git", "modules", "lib", "config")
	for _, f := range []string{filepath.Join(repo, ".git", "config"), nested, submodule} {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p := &profile.Profile{Mounts: []profile.Mount{{Path: repo, Mode: profile.ModeWrite}}}
	mounts := containerMounts(p, osHost{})
	for _, want := range []string{nested, submodule} {
		if !slices.Contains(mounts, containers.Mount{Path: want, ReadOnly: true}) {
			t.Errorf("%s is not read-only for containers: %+v", want, mounts)
		}
	}
}
