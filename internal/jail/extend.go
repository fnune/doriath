package jail

import (
	"cmp"
	"errors"
	"slices"

	"github.com/fnune/doriath/internal/profile"
)

// Promotion is a path that a running jail makes writable, with the paths
// inside it that stay read-only.
type Promotion struct {
	Path   string
	Guards []string
}

// Extension is what a running jail adds for the mounts of p: the paths it
// shows read-only, the paths it makes writable, outermost first, the paths
// it hides, and the guarded symlinks that doriath keeps in place instead.
type Extension struct {
	Read  []string
	Write []Promotion
	Hide  []string
	Links []string
}

// Extend plans the mounts of p for a jail that already runs. It returns
// the errors that would stop a session with p from starting.
func Extend(p *profile.Profile, host Host) (Extension, error) {
	binds, _, errs := mountBinds(p, Layout{}, host)
	kept, links, errs := splitGuardedLinks(binds, host, errs)
	if len(errs) > 0 {
		return Extension{}, errors.Join(errs...)
	}
	var readOnly, writable []string
	ext := Extension{Links: links}
	for _, b := range kept {
		switch {
		case b.Device:
		case b.Source != b.Dest:
			ext.Hide = append(ext.Hide, b.Dest)
		case b.ReadOnly:
			readOnly = append(readOnly, b.Dest)
		default:
			writable = append(writable, b.Dest)
		}
	}
	slices.SortFunc(writable, func(a, b string) int { return cmp.Compare(len(a), len(b)) })
	for _, w := range slices.Compact(writable) {
		promo := Promotion{Path: w}
		for _, r := range readOnly {
			if r != w && within(r, w) {
				promo.Guards = append(promo.Guards, r)
			}
		}
		ext.Write = append(ext.Write, promo)
	}
	slices.SortFunc(readOnly, func(a, b string) int { return cmp.Compare(len(a), len(b)) })
	for _, r := range readOnly {
		covered := func(root string) bool { return within(r, root) }
		if !slices.ContainsFunc(writable, covered) && !slices.ContainsFunc(ext.Read, covered) {
			ext.Read = append(ext.Read, r)
		}
	}
	return ext, nil
}
