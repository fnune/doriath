package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/cli"
	"github.com/fnune/doriath/internal/jail"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/promote"
)

// requestWrite asks you whether the agent may write path, and makes it
// writable when you allow it.
func (s *Session) requestWrite(path, reason string) (RequestResult, error) {
	path, err := s.checkPromotion(path)
	if err != nil {
		return RequestResult{}, err
	}
	details := "The agent asks to write " + path + ", which is read-only in the jail. An allow lasts until the session ends."
	if !s.visible(path) {
		if err := requireDirectory(path); err != nil {
			return RequestResult{}, err
		}
		details = "The agent asks to write " + path + ", which the jail does not show. An allow shows it, writable, until the session ends."
	}
	req := approval.Request{
		Session: s.id,
		Profile: s.req.Profile.Name,
		Kind:    approval.KindPath,
		Summary: "Let the agent write " + path,
		Details: details,
		Note:    reason,
		Keep:    s.mountLines(path),
		Scope:   "path write " + path,
	}
	s.warn(&req, path, false)
	return s.holdAndGrant(req, func() error { return s.grantWrite(context.Background(), path) })
}

func (s *Session) holdAndGrant(req approval.Request, grant func() error) (RequestResult, error) {
	granted := make(chan error, 1)
	d, id := s.manager.Hold(req, pendingTTL, s.deps.HostWait, func(d approval.Decision) {
		if d.Verdict == approval.VerdictAllow {
			granted <- grant()
		}
	})
	res := RequestResult{Decision: d}
	switch {
	case d.Verdict == approval.VerdictAllow && id == "":
		return res, grant()
	case d.Verdict == approval.VerdictAllow:
		select {
		case err := <-granted:
			return res, err
		default:
			return res, nil
		}
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
	asWriteMount := &profile.Profile{Mounts: []profile.Mount{{Path: path, Mode: profile.ModeWrite}}}
	listings := newListingCache()
	if err := s.holdControlPathsOf(asWriteMount, listings); err != nil {
		return err
	}
	guards, links, err := jail.GuardsAndLinks(asWriteMount, listings)
	if err != nil {
		return err
	}
	if err := jail.CheckLinks(asWriteMount, listings, guards...); err != nil {
		return err
	}
	if err := s.links.Keep(links...); err != nil {
		return err
	}
	err = s.deps.Promote(ctx, promote.Request{
		Reaper:  reaper,
		JailExe: jail.ExePath,
		HostExe: s.deps.Exe,
		Nsenter: s.deps.Nsenter,
		Unshare: s.deps.Unshare,
		Path:    path,
		Guards:  guards,
		Visible: s.visible(path),
	})
	if err != nil {
		return fmt.Errorf("make %s writable: %w", path, err)
	}
	s.mu.Lock()
	s.req.Profile.Mounts = append(s.req.Profile.Mounts, profile.Mount{Path: path, Mode: profile.ModeWrite})
	s.entry.AgentWritable = append(s.entry.AgentWritable, path)
	if s.entry.PID != 0 {
		s.saveEntry()
	}
	s.mu.Unlock()
	if s.containerBroker != nil {
		s.containerBroker.AllowWrite(path, guards)
	}
	s.log.Write("granted", map[string]any{"path": path, "mode": "write"})
	return nil
}

func (s *Session) mountLines(path string) string {
	return fmt.Sprintf("[[mounts]]\npath = %q\nmode = \"write\"", s.profilePath(path))
}

func (s *Session) checkPromotion(path string) (string, error) {
	return s.checkGrant(path, true)
}

func (s *Session) checkRead(path string) (string, error) {
	if filepath.IsAbs(path) {
		if err := requireDirectory(filepath.Clean(path)); err != nil {
			return "", err
		}
	}
	return s.checkGrant(path, false)
}

func (s *Session) checkGrant(path string, write bool) (string, error) {
	path, err := s.checkReach(path, write)
	if err != nil {
		return "", err
	}
	for _, part := range strings.Split(path, "/") {
		if part != ".git" && part != ".jj" {
			continue
		}
		if !write {
			return "", fmt.Errorf("%s: doriath does not show paths inside .git or .jj on their own", path)
		}
		return "", fmt.Errorf("%s: doriath does not make paths inside .git or .jj writable. To commit, branch and add worktrees in another repository, run: %s. In this session's repository, git and jj need no grant. To change .git/config, run: %s", path, cli.Code(cli.Line("request", "module", "MODULE", "REPOSITORY", "--reason", "TEXT")), cli.Code(cli.Line("request", "edit", "PATH", "--reason", "TEXT")+" < NEW_CONTENT"))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.req.Profile.Mounts {
		switch {
		case m.Mode == profile.ModeHide && (within(path, m.Path) || !write && within(m.Path, path)):
			return "", fmt.Errorf("%s: the profile hides %s", path, m.Path)
		case m.Path != path && within(m.Path, path):
			return "", fmt.Errorf("%s: it holds %s, which the jail mounts with its own guards, and a grant of the parent would cover them. Ask for a path beside it", path, m.Path)
		case write && m.Mode == profile.ModeWrite && within(path, m.Path):
			return "", fmt.Errorf("%s is already writable", path)
		case !write && m.Mode != profile.ModeHide && within(path, m.Path):
			return "", fmt.Errorf("%s is already readable", path)
		}
	}
	if write {
		if err := s.landlockAllows(path); err != nil {
			return "", err
		}
	}
	return path, nil
}

func (s *Session) landlockAllows(path string) error {
	if !slices.ContainsFunc(s.entry.Writable, func(root string) bool { return within(path, root) }) {
		return fmt.Errorf("%s: only paths under %s can become writable during a session, because Landlock fixes its rules when the jail starts; add it to [[mounts]] with mode = \"write\" instead", path, strings.Join(s.entry.Writable, ", "))
	}
	return nil
}

func (s *Session) checkReach(path string, write bool) (string, error) {
	verb := "show"
	if write {
		verb = "make writable"
	}
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
	for _, private := range s.privatePaths() {
		if within(path, private) || !write && within(private, path) {
			return "", fmt.Errorf("%s: doriath does not %s %s: it holds keys, logins, config that names programs the host runs, or doriath's own state", path, verb, private)
		}
	}
	if write && profile.UnderTrustedRoot(path+"/") {
		return "", fmt.Errorf("%s: credentials and egress programs trust programs under it by name", path)
	}
	for _, system := range []string{"/dev", "/proc", "/sys", "/run", "/var/tmp"} {
		if within(path, system) {
			return "", fmt.Errorf("%s: doriath does not %s system paths during a session", path, verb)
		}
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

func (s *Session) warn(req *approval.Request, path string, read bool) {
	w, ok := s.req.Profile.PathRules.Warning(path, read)
	if !ok {
		return
	}
	req.Warning = "The request touches " + w.Path + ". " + w.Reason
	req.Keep = ""
}

// privatePaths add the profile's refused paths and its caches to the paths
// doriath keeps private. A module layers read-only files in a cache, such
// as an agent's state, that a grant would make writable on the host.
func (s *Session) privatePaths() []string {
	out := append(s.deps.Paths.Private(), s.req.Profile.PathRules.Refuse...)
	for _, c := range s.req.Profile.Caches {
		out = append(out, c.Path)
	}
	return out
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
