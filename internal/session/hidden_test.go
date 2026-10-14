package session

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/fnune/doriath/internal/profile"
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
	if err := s.holdHiddenPaths(); err != nil {
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
	if err := s.holdHiddenPaths(); err != nil {
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
			if err := s.holdHiddenPaths(); err != nil {
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
