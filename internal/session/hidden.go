package session

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/fnune/girdle/internal/profile"
)

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
