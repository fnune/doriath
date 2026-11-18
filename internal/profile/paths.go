package profile

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// PathRules say what doriath does when the agent asks for a path, and which
// files it keeps read-only in writable mounts. They only restrict, so they
// stay out of Grants: a new entry does not ask you to allow the profile
// again.
type PathRules struct {
	// Refuse lists paths that no request reaches: a write of the path or
	// inside it, and also a read of a parent.
	Refuse []string
	Warn   []PathWarning
	Hold   []PathHold
}

type PathWarning struct {
	Path   string
	Reason string
	Read   bool
}

const MissingMove Missing = "move"

var holdStrictness = map[Missing]int{MissingSkip: 0, MissingMove: 1, MissingHold: 2}

type PathHold struct {
	Path    string
	Reason  string
	Missing Missing
	Folder  bool
}

func (r PathRules) Warning(path string, read bool) (PathWarning, bool) {
	touches := func(entry string) bool { return within(path, entry) || within(entry, path) }
	for _, w := range r.Warn {
		if (!read || w.Read) && touches(w.Path) {
			return w, true
		}
	}
	if read {
		return PathWarning{}, false
	}
	for _, h := range r.Hold {
		if touches(h.Path) {
			return PathWarning{Path: h.Path, Reason: h.Reason}, true
		}
	}
	return PathWarning{}, false
}

func (r PathRules) HoldsFolder(path string) bool {
	return slices.ContainsFunc(r.Hold, func(h PathHold) bool { return h.Path == path && h.Folder })
}

func (r PathRules) resolve(fill func(string) (string, bool)) PathRules {
	var out PathRules
	for _, p := range r.Refuse {
		if path, ok := fill(p); ok {
			out.Refuse = append(out.Refuse, path)
		}
	}
	for _, w := range r.Warn {
		if path, ok := fill(w.Path); ok {
			w.Path = path
			out.Warn = append(out.Warn, w)
		}
	}
	for _, h := range r.Hold {
		if path, ok := fill(h.Path); ok {
			h.Path = path
			out.Hold = append(out.Hold, h)
		}
	}
	return out
}

func heldMounts(mounts []Mount, holds []PathHold) []Mount {
	for _, h := range holds {
		enclosing, ok := deepestAbove(mounts, h.Path)
		if !ok || enclosing.Mode == ModeHide {
			continue
		}
		missing := h.Missing
		if missing == MissingMove {
			missing = MissingSkip
		}
		mounts = mergeKeepingLessAccess(mounts, Mount{Path: h.Path, Mode: ModeRead, Missing: missing})
	}
	return mounts
}

func deepestAbove(mounts []Mount, path string) (Mount, bool) {
	var out Mount
	found := false
	for _, m := range mounts {
		if m.Path != path && within(path, m.Path) && (!found || len(m.Path) > len(out.Path)) {
			out, found = m, true
		}
	}
	return out, found
}

type pathsLayer struct {
	Refuse []string    `toml:"refuse"`
	Warn   []warnLayer `toml:"warn"`
	Hold   []holdLayer `toml:"hold"`
}

type warnLayer struct {
	Path   string `toml:"path"`
	Reason string `toml:"reason"`
	Read   bool   `toml:"read"`
}

type holdLayer struct {
	Path    string `toml:"path"`
	Reason  string `toml:"reason"`
	Missing string `toml:"missing"`
	Folder  bool   `toml:"folder"`
}

func (b *builder) applyPaths(l *pathsLayer) {
	if l == nil {
		return
	}
	for _, p := range l.Refuse {
		b.refuse = appendNew(b.refuse, p)
	}
	for _, w := range l.Warn {
		if !slices.ContainsFunc(b.warn, func(x warnLayer) bool { return x.Path == w.Path }) {
			b.warn = append(b.warn, w)
		}
	}
	for _, h := range l.Hold {
		i := slices.IndexFunc(b.hold, func(x holdLayer) bool { return x.Path == h.Path })
		if i < 0 {
			b.hold = append(b.hold, h)
			continue
		}
		if holdStrictness[Missing(h.Missing)] > holdStrictness[Missing(b.hold[i].Missing)] {
			b.hold[i].Missing = h.Missing
		}
		b.hold[i].Folder = b.hold[i].Folder || h.Folder
	}
}

func (b *builder) buildPaths() (PathRules, []error) {
	var out PathRules
	var errs []error
	for _, raw := range b.refuse {
		path, err := b.listPath(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("paths refuse: %w", err))
			continue
		}
		out.Refuse = append(out.Refuse, path)
	}
	for _, w := range b.warn {
		path, err := b.listPath(w.Path)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("paths warn: %w", err))
		case strings.TrimSpace(w.Reason) == "":
			errs = append(errs, fmt.Errorf("paths warn %s: give a reason, which the request shows you", w.Path))
		default:
			out.Warn = append(out.Warn, PathWarning{Path: path, Reason: w.Reason, Read: w.Read})
		}
	}
	for _, h := range b.hold {
		path, err := b.listPath(h.Path)
		missing := Missing(h.Missing)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("paths hold: %w", err))
		case strings.TrimSpace(h.Reason) == "":
			errs = append(errs, fmt.Errorf("paths hold %s: give a reason, which a request for it shows you", h.Path))
		case missing != MissingHold && missing != MissingMove && missing != MissingSkip:
			errs = append(errs, fmt.Errorf("paths hold %s: missing %q: want move, hold or skip", h.Path, h.Missing))
		default:
			out.Hold = append(out.Hold, PathHold{Path: path, Reason: h.Reason, Missing: missing, Folder: h.Folder})
		}
	}
	return out, errs
}

func (b *builder) listPath(raw string) (string, error) {
	if raw != "/" && strings.HasSuffix(raw, "/") || slices.Contains(strings.Split(raw, "/"), "..") || raw != "/" && filepath.Clean(raw) != raw {
		return "", fmt.Errorf("path %q: write it without .., a trailing slash or repeated slashes", raw)
	}
	if path, placeholder := placeholderPath(raw); placeholder {
		if !strings.HasPrefix(path, Repository) {
			return "", fmt.Errorf("path %q: start it with /, ~ or %s", raw, Repository)
		}
		return path, nil
	}
	return b.expand(raw)
}
