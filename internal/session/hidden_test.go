package session

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/jail"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/vcs"
)

func TestMissingHiddenPathInAWritableMountGetsAPlaceholder(t *testing.T) {
	s := newTestSession(t, nil)
	work := filepath.Join(s.home, "work")
	mkdirAll(t, work)
	hidden := filepath.Join(work, "config", "nested", ".envrc")
	s.req.Profile.Mounts = []profile.Mount{
		{Path: work, Mode: profile.ModeWrite},
		{Path: hidden, Mode: profile.ModeHide},
	}
	if err := s.holdMissingPaths(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(hidden); err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
		t.Fatalf("placeholder: %v, %v", info, err)
	}
	s.cleanup()
	for _, p := range []string{hidden, filepath.Dir(hidden), filepath.Join(work, "config")} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s stays after the session: %v", p, err)
		}
	}
	if _, err := os.Lstat(work); err != nil {
		t.Errorf("the mount itself went: %v", err)
	}
}

func TestMissingReadOnlyPathInAWritableMountGetsAPlaceholder(t *testing.T) {
	s := newTestSession(t, nil)
	work := filepath.Join(s.home, "work")
	mkdirAll(t, work)
	guarded := filepath.Join(work, ".envrc")
	s.req.Profile.Mounts = []profile.Mount{
		{Path: work, Mode: profile.ModeWrite},
		{Path: guarded, Mode: profile.ModeRead, Missing: profile.MissingHold},
	}
	if err := s.holdMissingPaths(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(guarded); err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
		t.Fatalf("placeholder: %v, %v", info, err)
	}
	s.cleanup()
	if _, err := os.Lstat(guarded); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s stays after the session: %v", guarded, err)
	}
}

func TestPlaceholdersStayOutOfCommits(t *testing.T) {
	s := newTestSession(t, nil)
	work := filepath.Join(s.home, "work")
	mkdirAll(t, filepath.Join(work, ".git", "info"), filepath.Join(work, "web"))
	exclude := filepath.Join(work, ".git", "info", "exclude")
	if err := os.WriteFile(exclude, []byte("/build"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.req.Profile.Mounts = []profile.Mount{
		{Path: work, Mode: profile.ModeWrite},
		{Path: filepath.Join(work, ".mcp.json"), Mode: profile.ModeRead, Missing: profile.MissingHold},
		{Path: filepath.Join(work, "web", "config", ".env"), Mode: profile.ModeHide},
	}
	if err := s.holdMissingPaths(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exclude)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/build\n", "\n/.mcp.json\n", "\n/web/config\n"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("info/exclude lacks %q:\n%s", want, data)
		}
	}
	s.cleanup()
	if data, err := os.ReadFile(exclude); err != nil || string(data) != "/build" {
		t.Errorf("info/exclude after the session = %q, %v", data, err)
	}
}

func TestPlaceholderCleanupKeepsWhatSomeoneElsePutThere(t *testing.T) {
	s := newTestSession(t, nil)
	work := filepath.Join(s.home, "work")
	mkdirAll(t, work)
	config := filepath.Join(work, "config")
	hidden := filepath.Join(config, ".envrc")
	s.req.Profile.Mounts = []profile.Mount{
		{Path: work, Mode: profile.ModeWrite},
		{Path: hidden, Mode: profile.ModeHide},
	}
	if err := s.holdMissingPaths(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{hidden, filepath.Join(config, "other")} {
		if err := os.WriteFile(f, []byte("yours"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s.cleanup()
	for _, p := range []string{hidden, config} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s was removed although you wrote there: %v", p, err)
		}
	}
}

func TestHiddenPathsThatNeedNoPlaceholder(t *testing.T) {
	for _, c := range []struct {
		name, hide string
	}{
		{"an existing path", "work/.env"},
		{"a path outside every mount", "elsewhere/.envrc"},
		{"a path in a read-only mount", "docs/.envrc"},
		{"a writable mount itself", "own"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newTestSession(t, nil)
			work, existing := filepath.Join(s.home, "work"), filepath.Join(s.home, "work", ".env")
			mkdirAll(t, work, filepath.Join(s.home, "docs"))
			if err := os.WriteFile(existing, []byte("SECRET=1"), 0o600); err != nil {
				t.Fatal(err)
			}
			hide := filepath.Join(s.home, c.hide)
			s.req.Profile.Mounts = []profile.Mount{
				{Path: work, Mode: profile.ModeWrite},
				{Path: filepath.Join(s.home, "own"), Mode: profile.ModeWrite},
				{Path: filepath.Join(s.home, "docs"), Mode: profile.ModeRead},
				{Path: hide, Mode: profile.ModeHide},
			}
			if err := s.holdMissingPaths(); err != nil {
				t.Fatal(err)
			}
			defer s.cleanup()
			if hide == existing {
				if data, err := os.ReadFile(existing); err != nil || string(data) != "SECRET=1" {
					t.Errorf("the hidden file changed: %q, %v", data, err)
				}
				return
			}
			if _, err := os.Lstat(hide); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("%s was created: %v", hide, err)
			}
		})
	}
}

type countingHost struct {
	osHost
	lists int
}

func (c *countingHost) List(dir string) []jail.Entry {
	c.lists++
	return c.osHost.List(dir)
}

func TestHoldingControlPathsWalksAFolderOfManyWorktreesAFewTimesOnly(t *testing.T) {
	root := t.TempDir()
	for i := range 30 {
		if err := os.MkdirAll(filepath.Join(root, fmt.Sprintf("wt-%d", i), ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	p := &profile.Profile{Mounts: []profile.Mount{{Path: root, Mode: profile.ModeWrite}}}
	oneWalk := &countingHost{}
	jail.Repositories(root, oneWalk)

	roots, err := vcs.NewRootGuard(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	s := &Session{roots: roots}
	host := &countingHost{}
	if err := s.holdControlPathsOf(p, host); err != nil {
		t.Fatal(err)
	}
	if host.lists > 4*oneWalk.lists {
		t.Errorf("%d listings for %d in one walk: each placeholder must not walk the mount again", host.lists, oneWalk.lists)
	}
}

func TestAHeldJSONFileIsAnEmptyObjectSoThatToolsCanReadIt(t *testing.T) {
	s := newTestSession(t, nil)
	work := filepath.Join(s.home, "work")
	mkdirAll(t, work)
	settings := filepath.Join(work, ".claude", "settings.json")
	s.req.Profile.Mounts = []profile.Mount{
		{Path: work, Mode: profile.ModeWrite},
		{Path: settings, Mode: profile.ModeRead, Missing: profile.MissingHold},
	}
	if err := s.holdMissingPaths(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(settings); err != nil || string(data) != "{}\n" {
		t.Fatalf("placeholder = %q, %v", data, err)
	}
	s.cleanup()
	if _, err := os.Lstat(settings); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the untouched placeholder stays: %v", err)
	}
}

func TestAHeldFileThatSomeoneWroteStaysAfterTheSession(t *testing.T) {
	s := newTestSession(t, nil)
	work := filepath.Join(s.home, "work")
	mkdirAll(t, work)
	settings := filepath.Join(work, ".mcp.json")
	s.req.Profile.Mounts = []profile.Mount{
		{Path: work, Mode: profile.ModeWrite},
		{Path: settings, Mode: profile.ModeRead, Missing: profile.MissingHold},
	}
	if err := s.holdMissingPaths(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(`{"mcpServers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s.cleanup()
	if _, err := os.Lstat(settings); err != nil {
		t.Errorf("a file you wrote went: %v", err)
	}
}

func TestAHeldFolderIsAnEmptyFolderSoThatYourToolsCanStillWriteIntoIt(t *testing.T) {
	s := newTestSession(t, nil)
	work := filepath.Join(s.home, "work")
	mkdirAll(t, work)
	held := filepath.Join(work, ".idea")
	s.req.Profile.Mounts = []profile.Mount{
		{Path: work, Mode: profile.ModeWrite},
		{Path: held, Mode: profile.ModeRead, Missing: profile.MissingHold},
	}
	s.req.Profile.PathRules.Hold = []profile.PathHold{{Path: held, Reason: "r", Missing: profile.MissingHold, Folder: true}}
	if err := s.holdMissingPaths(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(held); err != nil || !info.IsDir() {
		t.Fatalf("placeholder: %v, %v", info, err)
	}
	s.cleanup()
	if _, err := os.Lstat(held); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s stays after the session: %v", held, err)
	}
}
