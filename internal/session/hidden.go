package session

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/fnune/doriath/internal/jail"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/term"
	"github.com/fnune/doriath/internal/vcs"
)

func (s *Session) holdControlPaths() error {
	s.showJJSecureConfigs()
	return s.holdControlPathsOf(s.req.Profile, s.listings)
}

// showJJSecureConfigs runs before the placeholders, so that jj in the jail
// reads each repository's secure config instead of migrating the
// placeholder of the legacy one. The jail sees each config read-only, where
// its own jj looks: under the jail's home, as yours is under yours.
func (s *Session) showJJSecureConfigs() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, jjRepo := range jail.JJRepos(s.req.Profile, s.listings) {
		dir, err := vcs.JJSecureConfig(ctx, s.vcsTools(), jjRepo)
		if err != nil {
			s.notes = append(s.notes, note{term.Warn, fmt.Sprintf("jj in the jail may fail in %s: %v", filepath.Dir(filepath.Dir(jjRepo)), err)})
			continue
		}
		if dir == "" {
			continue
		}
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			continue
		}
		s.placed = append(s.placed, jail.Bind{Source: dir, Dest: filepath.Join(s.deps.Paths.Home, ".config", "jj", "repos", filepath.Base(dir)), ReadOnly: true})
	}
}

// The placeholders stay: another session may still bind them.
func (s *Session) holdControlPathsOf(p *profile.Profile, host jail.Host) error {
	s.roots.Add(jail.GitRoots(p, host)...)
	holds := jail.Placeholders(p, host)
	paths := make([]string, len(holds))
	for i, h := range holds {
		paths[i] = h.Path
	}
	if err := jail.CheckLinks(p, host, paths...); err != nil {
		return err
	}
	for _, h := range holds {
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
		if errors.Is(err, fs.ErrExist) && isRegularFile(h.Path) {
			continue
		}
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

func isRegularFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
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
