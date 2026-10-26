package session

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/profile"
)

var shownNotRunKinds = []string{
	".csv", ".gif", ".htm", ".html", ".jpeg", ".jpg", ".json", ".log", ".markdown", ".md",
	".pdf", ".png", ".svg", ".toml", ".tsv", ".txt", ".webp", ".yaml", ".yml",
}

func (s *Session) requestOpenFile(u *url.URL, reason string) (RequestResult, error) {
	path, err := s.checkOpenFile(u)
	if err != nil {
		return RequestResult{}, err
	}
	req := approval.Request{
		Session: s.id,
		Profile: s.req.Profile.Name,
		Kind:    approval.KindOpen,
		Summary: "Open " + path + " on your machine?",
		Details: "The agent asks to open this file with the app that your machine uses for it:\n\n" + path + "\n\nThe jail shows this file, so the agent may have written it.",
		Note:    reason,
		Scope:   "open file " + path,
	}
	return s.holdAndGrant(req, func() error { return s.openFile(u) })
}

func (s *Session) checkOpenFile(u *url.URL) (string, error) {
	if u.Host != "" && !strings.EqualFold(u.Host, "localhost") {
		return "", fmt.Errorf("%s: doriath opens only files on this machine", u)
	}
	path := u.Path
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s: name an absolute path", u)
	}
	path = filepath.Clean(path)
	if real, err := filepath.EvalSymlinks(path); err != nil || real != path {
		return "", fmt.Errorf("%s: name an existing file, not through a symlink", path)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s: doriath opens only a regular file", path)
	}
	if info.Mode()&0o111 != 0 {
		return "", fmt.Errorf("%s: doriath does not open an executable file", path)
	}
	if !slices.Contains(shownNotRunKinds, strings.ToLower(filepath.Ext(path))) {
		return "", fmt.Errorf("%s: doriath opens only these kinds of file: %s", path, strings.Join(shownNotRunKinds, " "))
	}
	if !s.shownAsOnHost(path) {
		return "", fmt.Errorf("%s: the agent can open only files that the jail shows", path)
	}
	for _, private := range s.privatePaths() {
		if within(path, private) {
			return "", fmt.Errorf("%s: doriath does not open %s", path, private)
		}
	}
	return path, nil
}

func (s *Session) shownAsOnHost(path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	deepest := profile.Mount{Mode: profile.ModeHide}
	for _, m := range s.req.Profile.Mounts {
		if within(path, m.Path) && (len(m.Path) > len(deepest.Path) || len(m.Path) == len(deepest.Path) && m.Mode == profile.ModeHide) {
			deepest = m
		}
	}
	return deepest.Mode != profile.ModeHide
}

func (s *Session) openFile(u *url.URL) error {
	path, err := s.checkOpenFile(u)
	if err != nil {
		return err
	}
	if s.deps.Open == nil {
		return fmt.Errorf("this session cannot open files on the host")
	}
	if err := s.deps.Open(path); err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	s.log.Write("file-opened", map[string]string{"path": path})
	return nil
}
