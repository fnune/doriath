package session

import (
	"context"
	"errors"
	"fmt"
	"io"
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

type RequestModuleParams struct {
	Module string `json:"module"`
	Path   string `json:"path"`
	Reason string `json:"reason,omitempty"`
}

func moduleScope(module, root string) string { return "module " + module + " " + root }

func (s *Session) requestModule(module, path, reason string) (RequestResult, error) {
	root, ext, err := s.checkModule(module, path)
	if err != nil {
		return RequestResult{}, err
	}
	req := approval.Request{
		Session: s.id,
		Profile: s.req.Profile.Name,
		Kind:    approval.KindPath,
		Summary: "Let the agent use module " + module + " in " + root,
		Action:  "Use a module in a repository",
		Facts:   []approval.Fact{{Label: "Repository", Value: s.fromHome(root)}, {Label: "Module", Value: module}},
		Details: moduleDetails(module, root, ext),
		Note:    reason,
		Scope:   moduleScope(module, root),
	}
	s.warn(&req, root, false)
	return s.holdAndGrant(req, func() error { return s.grantModule(context.Background(), module, root) })
}

func moduleDetails(module, root string, ext *profile.Profile) string {
	var writable []string
	guarded := 0
	for _, m := range ext.Mounts {
		switch {
		case m.Mode == profile.ModeWrite:
			writable = append(writable, m.Path)
		case m.Path != root:
			guarded++
		}
	}
	guarded += len(ext.PathRules.Hold)
	var b strings.Builder
	fmt.Fprintf(&b, "The agent asks to use module %s in %s, as in a session that starts there. ", module, root)
	if len(writable) > 0 {
		fmt.Fprintf(&b, "It can write %s. ", strings.Join(writable, ", "))
	} else {
		b.WriteString("The checkout stays read-only. ")
	}
	if ext.VCSStore {
		b.WriteString("It can commit, make branches and add worktrees there, and doriath keeps your branches recoverable. ")
	}
	if guarded > 0 {
		fmt.Fprintf(&b, "The profile keeps %d paths there read-only, hidden or held, such as the files that git, direnv and your editor run. ", guarded)
	}
	b.WriteString("An allow lasts until the session ends.")
	return b.String()
}

func (s *Session) checkModule(module, path string) (string, *profile.Profile, error) {
	if !filepath.IsAbs(path) {
		return "", nil, fmt.Errorf("%s: name an absolute path", path)
	}
	exists := func(p string) bool { return osHost{}.Kind(p) != "" }
	root := profile.FindRepository(filepath.Clean(path), exists)
	switch root {
	case "":
		return "", nil, fmt.Errorf("%s is not in a git or jj repository, so no module applies to it. To write a plain folder, run: %s", path, cli.Code(cli.Line("request", "write", path, "--reason", "TEXT")))
	case s.repository:
		return "", nil, fmt.Errorf("%s is the repository of this session, where the profile applies already", root)
	}
	s.mu.Lock()
	applied := slices.Contains(s.modulesByRepository[root], module)
	s.mu.Unlock()
	if applied {
		return "", nil, fmt.Errorf("module %s applies in %s already", module, root)
	}
	ext, err := s.unresolved.ForRepository(module, root, s.deps.Paths.Home, exists)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", root, err)
	}
	write := ext.VCSStore || slices.ContainsFunc(ext.Mounts, func(m profile.Mount) bool { return m.Mode == profile.ModeWrite })
	if _, err := s.checkReach(root, write); err != nil {
		return "", nil, err
	}
	refused := append(s.privatePaths(), ext.PathRules.Refuse...)
	for _, m := range ext.Mounts {
		switch m.Mode {
		case profile.ModeWrite:
			if err := s.landlockAllows(m.Path); err != nil {
				return "", nil, err
			}
			if i := slices.IndexFunc(refused, func(r string) bool { return within(m.Path, r) || within(r, m.Path) }); i >= 0 {
				return "", nil, fmt.Errorf("%s: doriath does not make writable %s: it holds keys, logins, config that names programs the host runs, or doriath's own state", m.Path, refused[i])
			}
		case profile.ModeHide:
			if exists(m.Path) && !emptyPath(m.Path) {
				return "", nil, fmt.Errorf("%s: the profile hides it, and doriath cannot hide a path while the jail runs. Ask the user to start a session in %s instead", m.Path, root)
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	visible := slices.ContainsFunc(s.req.Profile.Mounts, func(m profile.Mount) bool { return m.Mode != profile.ModeHide && within(root, m.Path) })
	for _, m := range s.req.Profile.Mounts {
		switch {
		case m.Mode == profile.ModeHide && within(root, m.Path):
			return "", nil, fmt.Errorf("%s: the profile hides %s", root, m.Path)
		case !visible && m.Path != root && within(m.Path, root):
			return "", nil, fmt.Errorf("%s: it holds %s, which the jail mounts on its own, and doriath would cover it. Ask the user to start a session in %s instead", root, m.Path, root)
		}
	}
	return root, ext, nil
}

func emptyPath(path string) bool {
	info, err := os.Lstat(path)
	switch {
	case err != nil:
		return false
	case info.Mode().IsRegular():
		return info.Size() == 0
	case info.IsDir():
		f, err := os.Open(path)
		if err != nil {
			return false
		}
		defer f.Close()
		_, err = f.Readdirnames(1)
		return errors.Is(err, io.EOF)
	}
	return false
}

func (s *Session) grantModule(ctx context.Context, module, root string) error {
	root, ext, err := s.checkModule(module, root)
	if err != nil {
		return err
	}
	reaper := int(s.peers.init.Load())
	if reaper == 0 {
		return errors.New("the jail is not running yet")
	}
	listings := newListingCache()
	ext = withHookFolders(withLinkedStores(ext, listings), listings, gitHooksPath(s.deps.Git))
	for _, m := range ext.Mounts {
		if m.Create {
			if err := jail.CheckLinks(ext, osHost{}, m.Path); err != nil {
				return err
			}
			if err := os.MkdirAll(m.Path, 0o755); err != nil {
				return fmt.Errorf("create %s: %w", m.Path, err)
			}
		}
	}
	if err := s.holdMissingPaths(ext); err != nil {
		return err
	}
	if err := s.guardMissingHolds(ext); err != nil {
		s.log.Write("grant-warning", map[string]string{"path": root, "warning": err.Error()})
	}
	if err := s.holdControlPathsOf(ext, listings); err != nil {
		return err
	}
	configs, warnings := s.jjSecureConfigs(ext, listings)
	notes, err := s.addRepositories(ctx, ext, listings)
	for _, w := range append(warnings, notes...) {
		s.log.Write("grant-warning", map[string]string{"path": root, "warning": w})
	}
	if err != nil {
		return err
	}
	plan, err := jail.Extend(ext, newListingCache())
	if err != nil {
		return err
	}
	if err := guardEmptyHides(&plan); err != nil {
		return err
	}
	if err := s.links.Keep(plan.Links...); err != nil {
		return err
	}
	base := promote.Request{Reaper: reaper, JailExe: jail.ExePath, HostExe: s.deps.Exe, Nsenter: s.deps.Nsenter, Unshare: s.deps.Unshare}
	for _, path := range plan.Read {
		if s.visible(path) {
			continue
		}
		r := base
		r.Path = path
		if err := s.deps.Read(ctx, r); err != nil {
			return fmt.Errorf("show %s: %w", path, err)
		}
		s.addMounts(profile.Mount{Path: path, Mode: profile.ModeRead})
	}
	var writable []string
	for _, w := range plan.Write {
		r := base
		r.Path, r.Guards, r.Visible = w.Path, w.Guards, s.visible(w.Path)
		if err := s.deps.Promote(ctx, r); err != nil {
			return fmt.Errorf("make %s writable: %w", w.Path, err)
		}
		s.addMounts(profile.Mount{Path: w.Path, Mode: profile.ModeWrite})
		writable = append(writable, w.Path)
		if s.containerBroker != nil {
			s.containerBroker.AllowWrite(w.Path, w.Guards)
		}
	}
	for _, c := range configs {
		if s.visible(c.Dest) {
			continue
		}
		r := base
		r.Path, r.Dest = c.Source, c.Dest
		if err := s.deps.Read(ctx, r); err != nil {
			return fmt.Errorf("show the jj config of %s: %w", root, err)
		}
	}
	s.addMounts(ext.Mounts...)
	s.mu.Lock()
	rules := &s.req.Profile.PathRules
	rules.Refuse = append(rules.Refuse, ext.PathRules.Refuse...)
	rules.Warn = append(rules.Warn, ext.PathRules.Warn...)
	rules.Hold = append(rules.Hold, ext.PathRules.Hold...)
	s.modulesByRepository[root] = append(s.modulesByRepository[root], module)
	s.entry.AgentWritable = append(s.entry.AgentWritable, writable...)
	if s.entry.PID != 0 {
		s.saveEntry()
	}
	s.mu.Unlock()
	s.log.Write("granted", map[string]any{"path": root, "module": module, "writable": writable})
	return nil
}

func guardEmptyHides(plan *jail.Extension) error {
	for _, h := range plan.Hide {
		if !emptyPath(h) {
			return fmt.Errorf("%s: doriath cannot hide a path while the jail runs", h)
		}
		deepest := -1
		for i, w := range plan.Write {
			if h != w.Path && within(h, w.Path) && (deepest < 0 || len(w.Path) > len(plan.Write[deepest].Path)) {
				deepest = i
			}
		}
		if deepest >= 0 {
			plan.Write[deepest].Guards = append(plan.Write[deepest].Guards, h)
		}
	}
	return nil
}

func (s *Session) addMounts(mounts ...profile.Mount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range mounts {
		if !slices.ContainsFunc(s.req.Profile.Mounts, func(x profile.Mount) bool { return x.Path == m.Path && x.Mode == m.Mode }) {
			s.req.Profile.Mounts = append(s.req.Profile.Mounts, m)
		}
	}
}
