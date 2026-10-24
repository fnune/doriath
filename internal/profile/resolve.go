package profile

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

const (
	// Current is the directory doriath run starts in.
	Current = "{current}"
	// Repository is the root of the git or jj repository that holds
	// {current}. Entries that use it are skipped outside a repository.
	Repository = "{repository}"
)

func placeholderPath(p string) (string, bool) {
	for _, ph := range []string{Current, Repository} {
		if p == ph {
			return p, true
		}
		if rest, ok := strings.CutPrefix(p, ph+"/"); ok {
			return ph + "/" + strings.TrimPrefix(filepath.Clean("/"+rest), "/"), true
		}
	}
	return p, false
}

// CheckMount refuses mounts that would undo the jail in any mode: reading
// is what they expose.
func CheckMount(path, home string) error {
	switch {
	case path == "/":
		return errors.New("the agent would see the whole filesystem")
	case within(home, path):
		return errors.New("the agent would see your whole home directory: your keys, tokens and other projects")
	}
	return nil
}

func checkMode(path string, mode Mode) error {
	if mode == ModeWrite && !strings.HasPrefix(path, "{") && UnderTrustedRoot(path+"/") {
		return errors.New("must not be writable, because credentials and egress programs trust programs under it by name")
	}
	return nil
}

var privilege = map[Mode]int{ModeHide: 0, ModeRead: 1, ModeWrite: 2}

func mergeKeepingLessAccess(mounts []Mount, m Mount) []Mount {
	i := slices.IndexFunc(mounts, func(x Mount) bool { return x.Path == m.Path })
	if i < 0 {
		return append(mounts, m)
	}
	missing := mounts[i].OnMissing()
	if strictness[m.OnMissing()] > strictness[missing] {
		missing = m.OnMissing()
	}
	mounts[i].Missing = missing
	if privilege[m.Mode] < privilege[mounts[i].Mode] {
		mounts[i].Mode = m.Mode
	}
	if mounts[i].Edit == nil {
		mounts[i].Edit = m.Edit
	}
	return mounts
}

// FindRepository returns the root of the git or jj repository that holds
// dir, or "" outside one.
func FindRepository(dir string, exists func(string) bool) string {
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if exists(filepath.Join(d, ".git")) || exists(filepath.Join(d, ".jj")) {
			return d
		}
		if d == "/" || d == "." {
			return ""
		}
	}
}

// Start is where a session starts: the directory doriath run starts in, and
// the repository that holds it, if any.
type Start struct {
	Current    string
	Repository string
	Exists     func(string) bool
}

// Defaults are the entries doriath adds on its own. Each yields to any entry
// of the profile or its modules for the same path or a directory above it:
// there, you already said what the agent sees.
func (p *Profile) Defaults() []Mount {
	out := []Mount{{Path: Current, Mode: ModeRead}}
	if p.VCSStore {
		out = append(out, Mount{Path: Repository, Mode: ModeRead, Missing: MissingSkip})
	}
	return out
}

// Resolve returns the profile with its placeholders filled in for a session
// that starts at start, doriath's default entries added, and every mount
// checked again now that its path is known.
func (p *Profile) Resolve(start Start, home string) (*Profile, error) {
	out := *p
	out.Mounts = nil
	var errs []error
	resolve := func(m Mount) (Mount, bool) {
		path, placeholder := placeholderPath(m.Path)
		if !placeholder {
			return m, true
		}
		root := start.Current
		if strings.HasPrefix(path, Repository) {
			root = start.Repository
			if root == "" {
				return m, false
			}
		}
		_, rest, _ := strings.Cut(path, "}")
		m.Path = filepath.Clean(root + rest)
		m.Create = m.Mode == ModeWrite && rest != ""
		if err := CheckMount(m.Path, home); err != nil {
			errs = append(errs, fmt.Errorf("mount %s, which is %s here: %w", path, m.Path, err))
			return m, false
		}
		if err := checkMode(m.Path, m.Mode); err != nil {
			errs = append(errs, fmt.Errorf("mount %s, which is %s here: %w", path, m.Path, err))
			return m, false
		}
		return m, true
	}
	var explicit []Mount
	for _, m := range p.Mounts {
		if r, ok := resolve(m); ok {
			explicit = mergeKeepingLessAccess(explicit, r)
		}
	}
	for _, d := range p.Defaults() {
		r, ok := resolve(d)
		if ok && !slices.ContainsFunc(explicit, func(m Mount) bool { return within(r.Path, m.Path) }) {
			out.Mounts = mergeKeepingLessAccess(out.Mounts, r)
		}
	}
	out.Mounts = append(out.Mounts, explicit...)
	out.PathRules = p.PathRules.resolve(func(path string) (string, bool) {
		path, placeholder := placeholderPath(path)
		if !placeholder {
			return path, true
		}
		root := start.Current
		if strings.HasPrefix(path, Repository) {
			root = start.Repository
		}
		_, rest, _ := strings.Cut(path, "}")
		return filepath.Clean(root + rest), root != ""
	})
	out.Mounts = heldMounts(out.Mounts, out.PathRules.Hold)
	if guard, ok := repoProfilesGuard(out.Mounts, start); ok {
		out.Mounts = append(out.Mounts, guard)
	}
	return &out, errors.Join(errs...)
}

func repoProfilesGuard(mounts []Mount, start Start) (Mount, bool) {
	if start.Repository == "" {
		return Mount{}, false
	}
	dir := filepath.Join(start.Repository, RepoProfiles)
	if !slices.ContainsFunc(mounts, func(m Mount) bool { return m.Mode == ModeWrite && m.Path != dir && within(dir, m.Path) }) {
		return Mount{}, false
	}
	if slices.ContainsFunc(mounts, func(m Mount) bool { return m.Path == dir }) {
		return Mount{}, false
	}
	mode := ModeHide
	if start.Exists != nil && start.Exists(dir) {
		mode = ModeRead
	}
	return Mount{Path: dir, Mode: mode, Missing: MissingHold}, true
}
