package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/secret"
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
	p := &profile.Profile{Name: "p", Mounts: []profile.Mount{{Path: filepath.Join(root, "work"), Mode: profile.ModeRead}}}
	if err := checkHelpers(deps, p); err != nil {
		t.Fatalf("a read-only mount is fine: %v", err)
	}
	p.Mounts[0].Mode = profile.ModeWrite
	if err := checkHelpers(deps, p); err == nil || !strings.Contains(err.Error(), "the jail can write") {
		t.Fatalf("err = %v", err)
	}
}

func TestJJAndSecretCommandsInsideWritableMountsAreRefused(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "work", "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"jj", "rbw"} {
		if err := os.WriteFile(filepath.Join(bin, name), nil, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	paths := config.Paths{Home: root, Cache: filepath.Join(root, "cache")}
	p := &profile.Profile{Name: "p", Mounts: []profile.Mount{{Path: filepath.Join(root, "work"), Mode: profile.ModeWrite}}}
	if err := checkHelpers(Deps{Paths: paths, JJ: filepath.Join(bin, "jj")}, p); err == nil || !strings.Contains(err.Error(), "jj is inside") {
		t.Errorf("jj: err = %v", err)
	}
	p.Secrets = map[string]secret.Backend{"token": {Command: []string{filepath.Join(bin, "rbw"), "get", "token"}}}
	if err := checkHelpers(Deps{Paths: paths}, p); err == nil || !strings.Contains(err.Error(), "rbw is inside") {
		t.Errorf("secret command: err = %v", err)
	}
}

func TestEntryRefusesHelpersTheJailCouldReplace(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "work", "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	nsenter := filepath.Join(bin, "nsenter")
	if err := os.WriteFile(nsenter, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	e := Entry{AgentWritable: []string{filepath.Join(root, "work")}}
	if err := e.CheckHelper(nsenter); err == nil || !strings.Contains(err.Error(), "the jail can write") {
		t.Fatalf("err = %v", err)
	}
	if err := (Entry{AgentWritable: []string{filepath.Join(root, "cache")}}).CheckHelper(nsenter); err != nil {
		t.Fatalf("a helper outside the agent's paths: %v", err)
	}
}
