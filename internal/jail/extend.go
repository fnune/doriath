package jail

import (
	"cmp"
	"errors"
	"slices"

	"github.com/fnune/doriath/internal/profile"
)

type Promotion struct {
	Path   string
	Guards []string
}

type Extension struct {
	Read  []string
	Write []Promotion
	Hide  []string
	Links []string
}

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
