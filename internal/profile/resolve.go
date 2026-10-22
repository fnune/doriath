package profile

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// The placeholders a mount path may start with. They resolve when a session
// starts, so one profile serves many projects.
const (
	// Current is the directory doriath run starts in.
	Current = "{current}"
	// Repository is the root of the git or jj repository that holds
	// {current}. Entries that use it are skipped outside a repository.
	Repository = "{repository}"
)

// placeholderPath reports whether p starts with a placeholder, and cleans
// what follows it.
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

// mergeMount adds m, or, when an entry for the same path exists, keeps the
// lower privilege of the two: promotion, not a later layer, is the way to
// more access.
func mergeMount(mounts []Mount, m Mount) []Mount {
	i := slices.IndexFunc(mounts, func(x Mount) bool { return x.Path == m.Path })
	if i < 0 {
		return append(mounts, m)
	}
	if privilege[m.Mode] < privilege[mounts[i].Mode] {
		mounts[i].Mode = m.Mode
	}
	mounts[i].Optional = mounts[i].Optional && m.Optional
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
}

// Defaults are the entries doriath adds on its own. Each yields to any entry
// of the profile or its modules for the same path or a directory above it:
// there, you already said what the agent sees.
func (p *Profile) Defaults() []Mount {
	out := []Mount{{Path: Current, Mode: ModeRead}}
	if p.VCSStore {
		out = append(out, Mount{Path: Repository, Mode: ModeRead, Optional: true})
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
			explicit = mergeMount(explicit, r)
		}
	}
	for _, d := range p.Defaults() {
		r, ok := resolve(d)
		if ok && !slices.ContainsFunc(explicit, func(m Mount) bool { return within(r.Path, m.Path) }) {
			out.Mounts = mergeMount(out.Mounts, r)
		}
	}
	out.Mounts = append(out.Mounts, explicit...)
	return &out, errors.Join(errs...)
}
