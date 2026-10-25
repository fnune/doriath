package profile

import (
	"fmt"
	"slices"
	"strings"
)

// Push holds the refs that a git push updates, as its ref commands name them.
// Unread is true when some commands could not be read, such as a compressed
// push or one whose commands do not fit the part that the proxy reads.
type Push struct {
	Refs   []string
	Unread bool
}

// RefPattern matches git ref names segment by segment, as PathPattern matches
// paths: "*" is one segment and "**" any number of segments.
type RefPattern string

func ParseRefPattern(s string) (RefPattern, error) {
	if !strings.HasPrefix(s, "refs/") {
		return "", fmt.Errorf("ref pattern %q: must start with refs/, such as refs/heads/agent/**", s)
	}
	if err := checkSegments(strings.Split(s, "/")); err != nil {
		return "", fmt.Errorf("ref pattern %q: %w", s, err)
	}
	return RefPattern(s), nil
}

func (p RefPattern) Match(ref string) bool {
	return matchSegments(strings.Split(string(p), "/"), strings.Split(ref, "/"))
}

func (r Rule) matchRefs(push *Push) bool {
	if len(r.Refs) == 0 {
		return true
	}
	if push == nil || len(push.Refs) == 0 && !push.Unread {
		return false
	}
	matches := func(ref string) bool {
		return slices.ContainsFunc(r.Refs, func(p RefPattern) bool { return p.Match(ref) })
	}
	if r.Action == ActionAllow {
		return !push.Unread && !slices.ContainsFunc(push.Refs, func(ref string) bool { return !matches(ref) })
	}
	return push.Unread || slices.ContainsFunc(push.Refs, matches)
}
