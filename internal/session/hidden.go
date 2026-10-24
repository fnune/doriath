package session

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

// holdMissingPaths gives each missing hidden or read-only path inside a
// writable mount an empty placeholder for the session, which the jail then
// hides or shows read-only, so that the agent cannot create the very file
// the profile keeps from it, such as an .envrc. The placeholders, and
// directories made for them, go when the session ends, if nothing else was
// put there.
func (s *Session) holdMissingPaths() error {
	p := s.req.Profile
	for _, m := range p.Mounts {
		if m.Mode == profile.ModeWrite || m.OnMissing() != profile.MissingHold {
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
			return fmt.Errorf("hold %s: %w", m.Path, err)
		}
		content := placeholderContent(m.Path)
		f, err := os.OpenFile(m.Path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("hold %s: %w", m.Path, err)
		}
		_, err = f.WriteString(content)
		_ = f.Close()
		if err != nil {
			return fmt.Errorf("hold %s: %w", m.Path, err)
		}
		created = append(created, m.Path)
		include := excludeFromGit(created[0])
		s.closers = append(s.closers, func() {
			include()
			for i := len(created) - 1; i >= 0; i-- {
				if untouched(created[i], content) {
					_ = os.Remove(created[i])
				}
			}
		})
	}
	return nil
}

func placeholderContent(path string) string {
	if filepath.Ext(path) == ".json" {
		return "{}\n"
	}
	return ""
}

func untouched(path, content string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return true
	}
	if !info.Mode().IsRegular() || info.Size() != int64(len(content)) {
		return false
	}
	data, err := os.ReadFile(path)
	return err == nil && string(data) == content
}

// excludeFromGit lists a placeholder in the info/exclude of the git
// repository that holds it, so that git add and jj's snapshots leave it out
// of commits, and returns what takes it out again. Outside a git repository
// it does nothing.
func excludeFromGit(path string) func() {
	root, exclude := gitExcludeFile(filepath.Dir(path))
	if exclude == "" {
		return func() {}
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return func() {}
	}
	block := "# doriath holds this path for a session\n/" + gitPattern(filepath.ToSlash(rel)) + "\n"
	if info, err := os.Lstat(exclude); err == nil && !info.Mode().IsRegular() {
		return func() {}
	}
	if err := os.MkdirAll(filepath.Dir(exclude), 0o755); err != nil {
		return func() {}
	}
	f, err := os.OpenFile(exclude, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return func() {}
	}
	if info, err := f.Stat(); err == nil && info.Size() > 0 {
		block = "\n" + block
	}
	_, err = f.WriteString(block)
	if closeErr := f.Close(); err != nil || closeErr != nil {
		return func() {}
	}
	return func() {
		data, err := os.ReadFile(exclude)
		if err != nil {
			return
		}
		if rest := strings.Replace(string(data), block, "", 1); rest != string(data) {
			_ = os.WriteFile(exclude, []byte(rest), 0o644)
		}
	}
}

// gitExcludeFile finds the worktree root above dir and the info/exclude of
// its repository, which linked worktrees share with the main one.
func gitExcludeFile(dir string) (root, exclude string) {
	for d := dir; ; d = filepath.Dir(d) {
		dotGit := filepath.Join(d, ".git")
		info, err := os.Lstat(dotGit)
		switch {
		case err == nil && info.IsDir():
			return d, filepath.Join(dotGit, "info", "exclude")
		case err == nil && info.Mode().IsRegular():
			common, ok := commonGitDir(d, dotGit)
			if !ok {
				return "", ""
			}
			return d, filepath.Join(common, "info", "exclude")
		}
		if d == filepath.Dir(d) {
			return "", ""
		}
	}
}

func commonGitDir(root, gitFile string) (string, bool) {
	data, err := os.ReadFile(gitFile)
	if err != nil {
		return "", false
	}
	gitDir, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir: ")
	if !ok {
		return "", false
	}
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(root, gitDir)
	}
	common, err := os.ReadFile(filepath.Join(gitDir, "commondir"))
	if err != nil {
		return gitDir, true
	}
	c := strings.TrimSpace(string(common))
	if !filepath.IsAbs(c) {
		c = filepath.Join(gitDir, c)
	}
	return filepath.Clean(c), true
}

// gitPattern escapes the characters that gitignore patterns give a meaning.
func gitPattern(path string) string {
	var b strings.Builder
	for _, r := range path {
		if strings.ContainsRune(`\*?[!# `, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
