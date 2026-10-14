package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/fnune/girdle/internal/approval"
	"github.com/fnune/girdle/internal/jail"
	"github.com/fnune/girdle/internal/profile"
	"github.com/fnune/girdle/internal/promote"
)

// requestWrite asks you whether the agent may write path, and makes it
// writable when you allow it.
func (s *Session) requestWrite(path, reason string) (RequestWriteResult, error) {
	path, err := s.checkPromotion(path)
	if err != nil {
		return RequestWriteResult{}, err
	}
	details := "The agent asks to write " + path + ", which is read-only in the jail. An allow lasts until the session ends.\n" + s.profileHint(path)
	if reason != "" {
		details += "\nIts reason, written by the agent: " + reason
	}
	req := approval.Request{
		Session: s.id,
		Profile: s.req.Profile.Name,
		Kind:    approval.KindPath,
		Summary: "Let the agent write " + path,
		Details: details,
		Scope:   "path write " + path,
	}
	granted := make(chan error, 1)
	d, id := s.manager.Hold(req, pendingTTL, s.deps.HostWait, func(d approval.Decision) {
		if d.Verdict == approval.VerdictAllow {
			granted <- s.grantWrite(context.Background(), path)
		}
	})
	res := RequestWriteResult{Decision: d}
	switch {
	case d.Verdict == approval.VerdictAllow && id == "":
		return res, nil
	case d.Verdict == approval.VerdictAllow:
		return res, <-granted
	case d.Verdict == approval.VerdictNone:
		res.Pending = id
	}
	return res, nil
}

// grantWrite makes path writable in the running jail until the session
// ends.
func (s *Session) grantWrite(ctx context.Context, path string) error {
	path, err := s.checkPromotion(path)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", path, err)
		}
	}
	if real, err := filepath.EvalSymlinks(path); err != nil || real != path {
		return fmt.Errorf("%s goes through a symlink; name the directory it points to", path)
	}
	reaper := int(s.peers.init.Load())
	if reaper == 0 {
		return errors.New("the jail is not running yet")
	}
	err = promote.Writable(ctx, promote.Request{
		Reaper:  reaper,
		JailExe: jail.ExePath,
		HostExe: s.deps.Exe,
		Nsenter: s.deps.Nsenter,
		Unshare: s.deps.Unshare,
		Path:    path,
		Visible: s.visible(path),
	})
	if err != nil {
		return fmt.Errorf("make %s writable: %w", path, err)
	}
	s.mu.Lock()
	s.req.Profile.Mounts = append(s.req.Profile.Mounts, profile.Mount{Path: path, Mode: profile.ModeWrite})
	s.mu.Unlock()
	if s.containerBroker != nil {
		s.containerBroker.AllowWrite(path)
	}
	s.log.Write("granted", map[string]any{"path": path, "mode": "write"})
	return nil
}

// profileHint says how to keep a grant for later sessions. girdle does not
// edit the profile itself: it may come from nix, and you decide its shape.
func (s *Session) profileHint(path string) string {
	return fmt.Sprintf("To keep it for later sessions, add to profile %s:\n[[mounts]]\npath = %q\nmode = \"write\"", s.req.Profile.Name, s.profilePath(path))
}

// checkPromotion returns the clean path, or why girdle does not make it
// writable during a session.
func (s *Session) checkPromotion(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s: name an absolute path", path)
	}
	path = filepath.Clean(path)
	if existing := deepestExisting(path); existing != "" {
		if real, err := filepath.EvalSymlinks(existing); err != nil || real != existing {
			return "", fmt.Errorf("%s goes through a symlink; name the directory it points to", path)
		}
	}
	if err := profile.CheckMount(path, s.deps.Paths.Home); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	if profile.UnderTrustedRoot(path + "/") {
		return "", fmt.Errorf("%s: credentials and egress programs trust programs under it by name", path)
	}
	for _, system := range []string{"/dev", "/proc", "/sys", "/run"} {
		if within(path, system) {
			return "", fmt.Errorf("%s: girdle does not make system paths writable", path)
		}
	}
	for _, part := range strings.Split(path, "/") {
		if part == ".git" || part == ".jj" {
			return "", fmt.Errorf("%s: girdle does not make paths inside .git or .jj writable; the vcs module makes the store writable", path)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.req.Profile.Mounts {
		if m.Mode == profile.ModeHide && within(path, m.Path) {
			return "", fmt.Errorf("%s: the profile hides %s", path, m.Path)
		}
		if m.Mode == profile.ModeWrite && within(path, m.Path) {
			return "", fmt.Errorf("%s is already writable", path)
		}
	}
	if !slices.ContainsFunc(s.entry.Writable, func(root string) bool { return within(path, root) }) {
		return "", fmt.Errorf("%s: only paths under %s can become writable during a session, because Landlock fixes its rules when the jail starts; add it to [[mounts]] with mode = \"write\" instead", path, strings.Join(s.entry.Writable, ", "))
	}
	return path, nil
}

// deepestExisting returns path or its closest ancestor that exists.
func deepestExisting(path string) string {
	for p := path; ; p = filepath.Dir(p) {
		if _, err := os.Lstat(p); err == nil {
			return p
		}
		if p == "/" {
			return ""
		}
	}
}

func (s *Session) visible(path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.req.Profile.Mounts {
		if m.Mode != profile.ModeHide && within(path, m.Path) {
			return true
		}
	}
	return false
}

// profilePath writes path relative to the repository when it is inside it,
// so the profile entry serves every repository the profile is used in.
func (s *Session) profilePath(path string) string {
	if s.repository != "" && within(path, s.repository) {
		rel, _ := filepath.Rel(s.repository, path)
		if rel == "." {
			return profile.Repository
		}
		return profile.Repository + "/" + rel
	}
	return path
}
