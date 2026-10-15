package session

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/fnune/girdle/internal/jail"
	"github.com/fnune/girdle/internal/profile"
)

func (s *Session) holdControlPaths() error {
	for _, h := range jail.Placeholders(s.req.Profile, osHost{}) {
		if err := jail.CheckLinks(s.req.Profile, osHost{}, h.Path); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(h.Path), 0o755); err != nil {
			return fmt.Errorf("hold %s: %w", h.Path, err)
		}
		if h.Dir {
			if err := os.Mkdir(h.Path, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
				return fmt.Errorf("hold %s: %w", h.Path, err)
			}
			continue
		}
		f, err := os.OpenFile(h.Path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o644)
		if err != nil {
			return fmt.Errorf("hold %s: %w", h.Path, err)
		}
		_, err = f.WriteString(h.Content)
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return fmt.Errorf("hold %s: %w", h.Path, err)
		}
	}
	return nil
}

// holdHiddenPaths gives each missing hidden path inside a writable mount an
// empty placeholder for the session, which the jail then hides, so that the
// agent cannot create the very file the profile hides, such as an .envrc.
// The placeholders, and directories made for them, go when the session
// ends, if nothing else was put there.
func (s *Session) holdHiddenPaths() error {
	p := s.req.Profile
	for _, m := range p.Mounts {
		if m.Mode != profile.ModeHide {
			continue
		}
		if _, err := os.Lstat(m.Path); !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if !slices.ContainsFunc(p.Mounts, func(w profile.Mount) bool {
			return w.Mode == profile.ModeWrite && within(m.Path, w.Path) && m.Path != w.Path
		}) {
			continue
		}
		if err := jail.CheckLinks(p, osHost{}, m.Path); err != nil {
			return err
		}
		var created []string
		for dir := filepath.Dir(m.Path); ; dir = filepath.Dir(dir) {
			if _, err := os.Lstat(dir); err == nil {
				break
			}
			created = append([]string{dir}, created...)
		}
		if err := os.MkdirAll(filepath.Dir(m.Path), 0o755); err != nil {
			return fmt.Errorf("hide %s: %w", m.Path, err)
		}
		f, err := os.OpenFile(m.Path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("hide %s: %w", m.Path, err)
		}
		_ = f.Close()
		created = append(created, m.Path)
		s.closers = append(s.closers, func() {
			for i := len(created) - 1; i >= 0; i-- {
				if info, err := os.Lstat(created[i]); err == nil && (info.IsDir() || info.Size() == 0) {
					_ = os.Remove(created[i])
				}
			}
		})
	}
	return nil
}
