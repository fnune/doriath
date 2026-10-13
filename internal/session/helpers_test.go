package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fnune/girdle/internal/config"
	"github.com/fnune/girdle/internal/profile"
)

func TestHelpersInsideWritableMountsAreRefused(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "work", "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	git := filepath.Join(bin, "git")
	if err := os.WriteFile(git, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	deps := Deps{Paths: config.Paths{Home: root, Cache: filepath.Join(root, "cache")}, Git: git}
	p := &profile.Profile{Name: "p", Mounts: []profile.Mount{{Path: filepath.Join(root, "work"), Mode: profile.ModeReadOnly}}}
	if err := checkHelpers(deps, p); err != nil {
		t.Fatalf("a read-only mount is fine: %v", err)
	}
	p.Mounts[0].Mode = profile.ModeReadWrite
	if err := checkHelpers(deps, p); err == nil || !strings.Contains(err.Error(), "the jail can write") {
		t.Fatalf("err = %v", err)
	}
}
