package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/jail"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/promote"
)

type RequestReadParams struct {
	Path string `json:"path"`
	// Reason is the agent's own text, shown to you as such.
	Reason string `json:"reason,omitempty"`
}

func (s *Session) requestRead(path, reason string) (RequestWriteResult, error) {
	path, err := s.checkRead(path)
	if err != nil {
		return RequestWriteResult{}, err
	}
	req := approval.Request{
		Session: s.id,
		Profile: s.req.Profile.Name,
		Kind:    approval.KindRead,
		Summary: "Let the agent read " + path,
		Details: "The agent asks to read " + path + ", which the jail does not show. An allow shows it, read-only, until the session ends.",
		Note:    reason,
		Keep:    fmt.Sprintf("[[mounts]]\npath = %q", s.profilePath(path)),
		Scope:   "path read " + path,
	}
	granted := make(chan error, 1)
	d, id := s.manager.Hold(req, pendingTTL, s.deps.HostWait, func(d approval.Decision) {
		if d.Verdict == approval.VerdictAllow {
			granted <- s.grantRead(context.Background(), path)
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

func (s *Session) grantRead(ctx context.Context, path string) error {
	path, err := s.checkRead(path)
	if err != nil {
		return err
	}
	reaper := int(s.peers.init.Load())
	if reaper == 0 {
		return errors.New("the jail is not running yet")
	}
	err = s.deps.Read(ctx, promote.Request{
		Reaper:  reaper,
		JailExe: jail.ExePath,
		HostExe: s.deps.Exe,
		Nsenter: s.deps.Nsenter,
		Unshare: s.deps.Unshare,
		Path:    path,
	})
	if err != nil {
		return fmt.Errorf("show %s: %w", path, err)
	}
	s.mu.Lock()
	s.req.Profile.Mounts = append(s.req.Profile.Mounts, profile.Mount{Path: path, Mode: profile.ModeRead})
	s.mu.Unlock()
	s.log.Write("granted", map[string]any{"path": path, "mode": "read"})
	return nil
}

func (s *Session) checkRead(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s: name an absolute path", path)
	}
	path = filepath.Clean(path)
	if err := requireDirectory(path); err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(path); err != nil || real != path {
		return "", fmt.Errorf("%s goes through a symlink; name the directory it points to", path)
	}
	if err := profile.CheckMount(path, s.deps.Paths.Home); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	for _, private := range s.privatePaths() {
		if within(path, private) || within(private, path) {
			return "", fmt.Errorf("%s: doriath does not show %s: it holds keys, logins, config that names programs the host runs, or doriath's own state", path, private)
		}
	}
	for _, system := range []string{"/dev", "/proc", "/sys", "/run", "/var/tmp"} {
		if within(path, system) {
			return "", fmt.Errorf("%s: doriath does not show system paths during a session", path)
		}
	}
	for _, part := range strings.Split(path, "/") {
		if part == ".git" || part == ".jj" {
			return "", fmt.Errorf("%s: doriath does not show paths inside .git or .jj on their own", path)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.req.Profile.Mounts {
		if m.Mode == profile.ModeHide && (within(path, m.Path) || within(m.Path, path)) {
			return "", fmt.Errorf("%s: the profile hides %s", path, m.Path)
		}
	}
	for _, m := range s.req.Profile.Mounts {
		if m.Mode != profile.ModeHide && within(path, m.Path) {
			return "", fmt.Errorf("%s is already readable", path)
		}
	}
	return path, nil
}

func requireDirectory(path string) error {
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("%s does not exist: ask the user to create it, then ask again", path)
	case err != nil:
		return err
	case !info.IsDir():
		return fmt.Errorf("%s is a file: ask for the directory that holds it", path)
	}
	return nil
}
