package session

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/fnune/doriath/internal/modules"
	"github.com/fnune/doriath/internal/profile"
)

func TestAHeldFileThatTheAgentCreatesIsMovedOutAndReported(t *testing.T) {
	s := newTestSession(t, nil)
	repo := filepath.Join(s.home, "repo")
	mkdirAll(t, repo)
	held := filepath.Join(repo, "lefthook-local.yml")
	nested := filepath.Join(repo, ".config", "lefthook.yml")
	s.req.Profile.Mounts = []profile.Mount{{Path: repo, Mode: profile.ModeWrite}}
	s.req.Profile.PathRules.Hold = []profile.PathHold{
		{Path: held, Reason: "lefthook runs it.", Missing: profile.MissingMove},
		{Path: nested, Reason: "lefthook runs it.", Missing: profile.MissingMove},
	}
	if err := s.guardMissingHolds(s.req.Profile); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(held, []byte("pre-commit: {commands: {x: {run: evil}}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mkdirAll(t, filepath.Dir(nested))
	if err := os.WriteFile(nested, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(s.deps.Paths.Moved(s.id), "lefthook-local.yml")
	waitFor(t, func() bool {
		_, err := os.Lstat(filepath.Join(s.deps.Paths.Moved(s.id), ".config", "lefthook.yml"))
		return err == nil && !exists(held) && !exists(nested)
	}, "the created files stay in the repository")
	if data, err := os.ReadFile(moved); err != nil || !strings.Contains(string(data), "evil") {
		t.Errorf("moved file: %q, %v", data, err)
	}
	s.cleanup()
	if !strings.Contains(s.audit.String(), `"held-moved"`) || !strings.Contains(s.audit.String(), moved) {
		t.Errorf("audit = %s", s.audit.String())
	}
}

func TestAMissingHeldFileGetsNoPlaceholderOnYourMachine(t *testing.T) {
	s := newTestSession(t, nil)
	repo := filepath.Join(s.home, "repo")
	mkdirAll(t, repo)
	if err := os.WriteFile(filepath.Join(repo, "lefthook.yaml"), []byte("pre-commit: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	l := &profile.Loader{Profiles: fstest.MapFS{"p.toml": {Data: []byte("modules = [\"vcs-readwrite\"]\n")}}, Modules: []fs.FS{modules.FS}, Home: s.home, Builtins: modules.Builtins}
	p, err := l.Load("p")
	if err != nil {
		t.Fatal(err)
	}
	if s.req.Profile, err = p.Resolve(profile.Start{Current: repo, Repository: repo}, s.home); err != nil {
		t.Fatal(err)
	}
	if err := s.holdMissingPaths(s.req.Profile); err != nil {
		t.Fatal(err)
	}
	if err := s.guardMissingHolds(s.req.Profile); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"lefthook.yml", ".envrc", "flake.nix", ".lefthook"} {
		if exists(filepath.Join(repo, name)) {
			t.Errorf("%s appears on your machine", name)
		}
	}
	if info, err := os.Lstat(filepath.Join(repo, ".vscode")); err != nil || !info.IsDir() {
		t.Errorf(".vscode is held with an empty folder: %v, %v", info, err)
	}
	if data, err := os.ReadFile(filepath.Join(repo, ".claude", "settings.json")); err != nil || string(data) != "{}\n" {
		t.Errorf("agent settings are held with {}: %q, %v", data, err)
	}
	s.cleanup()
	if data, err := os.ReadFile(filepath.Join(repo, "lefthook.yaml")); err != nil || string(data) != "pre-commit: {}\n" {
		t.Errorf("your own config changed: %q, %v", data, err)
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return !errors.Is(err, fs.ErrNotExist)
}

func TestAHeldPathBehindASymlinkThatTheAgentMadeIsLeftAlone(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	victim := filepath.Join(root, "other", ".config")
	for _, d := range []string{repo, victim} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	precious := filepath.Join(victim, "lefthook.yml")
	if err := os.WriteFile(precious, []byte("user data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(repo, ".config")); err != nil {
		t.Fatal(err)
	}
	hold := guardedHold{PathHold: profile.PathHold{Path: filepath.Join(repo, ".config", "lefthook.yml"), Missing: profile.MissingMove}, root: repo}
	var reported []error
	g, err := newMoveGuard([]guardedHold{hold}, filepath.Join(root, "moved"), func(path, moved, reason string, err error) {
		if moved != "" {
			t.Errorf("moved %s to %s", path, moved)
		}
		reported = append(reported, err)
	})
	if err != nil {
		t.Skip(err)
	}
	defer g.Close()
	g.sweep()
	if _, err := os.Stat(precious); err != nil {
		t.Fatalf("doriath moved a file that lies outside the mount: %v", err)
	}
	if len(reported) != 1 || reported[0] == nil {
		t.Errorf("the planted symlink must be reported once as an error: %v", reported)
	}
}

func TestAHeldPathThatTheAgentCreatesIsMovedOutOfTheMount(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".config"), 0o755); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(repo, ".config", "lefthook.yml")
	if err := os.WriteFile(planted, []byte("pre-commit: {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	hold := guardedHold{PathHold: profile.PathHold{Path: planted, Missing: profile.MissingMove}, root: repo}
	var moved string
	g, err := newMoveGuard([]guardedHold{hold}, filepath.Join(root, "moved"), func(_, to, _ string, err error) {
		if err != nil {
			t.Error(err)
		}
		moved = to
	})
	if err != nil {
		t.Skip(err)
	}
	defer g.Close()
	if _, err := os.Lstat(planted); err == nil || moved == "" {
		t.Fatalf("the planted file stays; moved to %q", moved)
	}
}
