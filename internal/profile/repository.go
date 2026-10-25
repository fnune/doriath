package profile

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// RepositoryGrant is what a module grants in {repository} and {current}:
// the paths it makes writable there, and whether it opens the store. It
// includes the modules that the module builds on.
type RepositoryGrant struct {
	Writes []string
	Store  bool
}

func (b *builder) recordRepositoryGrant(l layer) {
	var g RepositoryGrant
	for _, name := range l.Modules {
		inc := b.repositoryGrants[name]
		for _, w := range inc.Writes {
			g.Writes = appendNew(g.Writes, w)
		}
		g.Store = g.Store || inc.Store
	}
	for _, m := range l.Mounts {
		if path, placeholder := placeholderPath(m.Path); placeholder && m.Mode == string(ModeWrite) {
			g.Writes = appendNew(g.Writes, path)
		}
	}
	if l.VCS != nil && l.VCS.Store != nil && *l.VCS.Store {
		g.Store = true
	}
	b.repositoryGrants[l.source] = g
}

// ForRepository returns the entries that a session which starts in root
// gets from the profile, with the grants of module only: its writable
// paths and its store. Every entry that keeps a path read-only, hidden or
// held comes along, whichever module or profile sets it. Entries without a
// placeholder stay out, because the session already has them.
func (p *Profile) ForRepository(module, root, home string, exists func(string) bool) (*Profile, error) {
	g, ok := p.RepositoryGrants[module]
	if !ok {
		return nil, fmt.Errorf("the profile does not use module %q. It uses: %s", module, strings.Join(p.Modules, ", "))
	}
	if len(g.Writes) == 0 && !g.Store {
		return nil, fmt.Errorf("module %q grants nothing in a repository", module)
	}
	out := &Profile{Name: p.Name, GitEdits: p.GitEdits, VCSStore: g.Store && p.VCSStore}
	for _, m := range p.Mounts {
		path, placeholder := placeholderPath(m.Path)
		if !placeholder || m.Mode == ModeWrite && !slices.Contains(g.Writes, path) {
			continue
		}
		out.Mounts = append(out.Mounts, m)
	}
	if !slices.ContainsFunc(out.Mounts, func(m Mount) bool { return m.Mode == ModeWrite }) && !out.VCSStore {
		return nil, errors.New("the profile keeps what module " + module + " grants in a repository read-only")
	}
	out.PathRules = p.PathRules.placeholdersOnly()
	return out.Resolve(Start{Current: root, Repository: root, Exists: exists}, home)
}

func (r PathRules) placeholdersOnly() PathRules {
	isPlaceholder := func(path string) bool {
		_, ok := placeholderPath(path)
		return ok
	}
	var out PathRules
	for _, p := range r.Refuse {
		if isPlaceholder(p) {
			out.Refuse = append(out.Refuse, p)
		}
	}
	for _, w := range r.Warn {
		if isPlaceholder(w.Path) {
			out.Warn = append(out.Warn, w)
		}
	}
	for _, h := range r.Hold {
		if isPlaceholder(h.Path) {
			out.Hold = append(out.Hold, h)
		}
	}
	return out
}

// RepositoryModules lists the modules of the profile that grant something
// in a repository, for a session to apply in another one.
func (p *Profile) RepositoryModules() []string {
	var out []string
	for _, name := range p.Modules {
		if g := p.RepositoryGrants[name]; len(g.Writes) > 0 || g.Store && p.VCSStore {
			out = append(out, name)
		}
	}
	return out
}
