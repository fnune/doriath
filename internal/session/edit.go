package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/edit"
	"github.com/fnune/doriath/internal/jail"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/vcs"
)

const MethodRequestEdit = "path.request_edit"

type RequestEditParams struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Reason  string `json:"reason,omitempty"`
}

type RequestEditResult struct {
	Decision approval.Decision `json:"decision"`
	Pending  string            `json:"pending,omitempty"`
	Changes  string            `json:"changes,omitempty"`
}

func (s *Session) requestEdit(path, content, reason string) (RequestEditResult, error) {
	path, rule, err := s.editRule(path)
	if err != nil {
		return RequestEditResult{}, err
	}
	checked, err := edit.Check(path)
	if err != nil {
		return RequestEditResult{}, err
	}
	ctx := context.Background()
	changes, err := edit.Changes(ctx, s.deps.Git, rule.Format, checked.Content, []byte(content))
	if err != nil {
		return RequestEditResult{}, fmt.Errorf("%s: %w", path, err)
	}
	described := edit.Describe(changes, rule.Safe)
	res := RequestEditResult{Changes: described}
	if len(changes) == 0 {
		res.Decision = approval.Decision{Verdict: approval.VerdictAllow, By: "doriath"}
		return res, nil
	}
	apply := func() error { return edit.Apply(ctx, s.deps.Git, checked, rule.Format, []byte(content), changes) }
	_, warned := s.req.Profile.PathRules.Warning(path, false)
	if !warned && !slices.ContainsFunc(changes, func(c edit.Change) bool { return !edit.Safe(c, rule.Safe) }) {
		s.log.Write("edit", map[string]any{"path": path, "changes": described, "by": "rule"})
		res.Decision = approval.Decision{Verdict: approval.VerdictAllow, By: "doriath"}
		return res, apply()
	}
	if len(described) > approval.MaxFact {
		return RequestEditResult{}, fmt.Errorf("%s: the changes are longer than %d bytes, which is more than doriath can show you. Ask for fewer changes at once", path, approval.MaxFact)
	}
	sum := sha256.Sum256([]byte(content))
	req := approval.Request{
		Session: s.id,
		Profile: s.req.Profile.Name,
		Kind:    approval.KindEdit,
		Summary: "Change " + path,
		Action:  "Change a file",
		Facts:   []approval.Fact{{Label: "File", Value: s.fromHome(path)}, {Label: "Changes", Value: described}},
		Details: "The agent asks to change " + path + ", which is read-only in the jail. doriath writes these changes once:\n" + described,
		Note:    reason,
		Scope:   "edit " + path + " " + hex.EncodeToString(sum[:8]),
	}
	s.warn(&req, path, false)
	applied := make(chan error, 1)
	d, id := s.manager.Hold(req, pendingTTL, s.deps.HostWait, func(d approval.Decision) {
		if d.Verdict == approval.VerdictAllow {
			applied <- apply()
		}
	})
	res.Decision = d
	switch {
	case d.Verdict == approval.VerdictAllow && id == "":
		return res, apply()
	case d.Verdict == approval.VerdictAllow:
		select {
		case err := <-applied:
			return res, err
		default:
			return res, nil
		}
	case d.Verdict == approval.VerdictNone:
		res.Pending = id
	}
	return res, nil
}

func (s *Session) editRule(path string) (string, *profile.Edit, error) {
	if !filepath.IsAbs(path) {
		return "", nil, fmt.Errorf("%s: name an absolute path", path)
	}
	path = filepath.Clean(path)
	if real, err := filepath.EvalSymlinks(path); err != nil || real != path {
		return "", nil, fmt.Errorf("%s: name an existing file, not through a symlink", path)
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("%s: only a regular file can be edited", path)
	}
	if !s.visible(path) {
		return "", nil, fmt.Errorf("%s: the agent can edit only what it sees", path)
	}
	for _, private := range s.privatePaths() {
		if within(path, private) {
			return "", nil, fmt.Errorf("%s: doriath does not edit %s: it holds keys, logins, config that names programs the host runs, or doriath's own state", path, private)
		}
	}
	if e := s.req.Profile.GitEdits[filepath.Base(path)]; e != nil && s.knownStore(filepath.Dir(path)) {
		return path, e, nil
	}
	s.mu.Lock()
	mounts := slices.Clone(s.req.Profile.Mounts)
	s.mu.Unlock()
	if i := slices.IndexFunc(mounts, func(m profile.Mount) bool { return m.Path == path && m.Edit != nil }); i >= 0 {
		return path, mounts[i].Edit, nil
	}
	if !readOnlyInJail(path, s.writable(nil), mounts, jail.Guards(s.req.Profile, osHost{})) {
		return "", nil, fmt.Errorf("%s is writable in the jail: write it directly", path)
	}
	return path, &profile.Edit{Format: profile.FormatText}, nil
}

func (s *Session) knownStore(dir string) bool {
	return vcs.IsStore(dir, osHost{}) && slices.Contains(s.knownStores(), dir)
}

func (s *Session) knownStores() []string {
	var repos []string
	if s.repository != "" {
		repos = append(repos, s.repository)
	}
	s.mu.Lock()
	for root := range s.modulesByRepository {
		repos = append(repos, root)
	}
	s.mu.Unlock()
	if s.listings != nil {
		s.listings.mu.Lock()
		for _, found := range s.listings.repos {
			repos = append(repos, found...)
		}
		s.listings.mu.Unlock()
	}
	var stores []string
	for _, repo := range repos {
		if filepath.Base(repo) == ".git" {
			stores = append(stores, repo)
			continue
		}
		git, jj := vcs.Linked(repo)
		stores = append(stores, vcs.Store(repo), git, jj)
	}
	return stores
}

func readOnlyInJail(path string, writable []string, mounts []profile.Mount, guards []string) bool {
	deepest, readOnly := "", false
	consider := func(root string, ro bool) {
		if within(path, root) && (len(root) > len(deepest) || len(root) == len(deepest) && ro) {
			deepest, readOnly = root, ro
		}
	}
	for _, w := range writable {
		consider(w, false)
	}
	for _, m := range mounts {
		if m.Mode != profile.ModeHide {
			consider(m.Path, m.Mode == profile.ModeRead)
		}
	}
	for _, g := range guards {
		consider(g, true)
	}
	return readOnly
}
