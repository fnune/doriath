package containers

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
)

// Resolver resolves symbolic links in a path, as filepath.EvalSymlinks does.
// Without it, an agent could bind a link inside its worktree that points
// anywhere the podman service can see.
type Resolver interface {
	EvalSymlinks(p string) (string, error)
}

var volumeName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

type access struct {
	write        bool
	nonRecursive bool
}

func (c checker) bindSource(src string, a access) string {
	if !path.IsAbs(src) {
		return fmt.Sprintf("bind source %q is not an absolute path", src)
	}
	resolved := c.resolve(path.Clean(src))
	m, ok := c.mountFor(resolved)
	if !ok {
		return fmt.Sprintf("binding %s into a container is not allowed: it is outside the mounts and caches of profile %q; add it to [[mounts]] to allow it", src, c.profile)
	}
	if m.Hidden {
		return fmt.Sprintf("binding %s into a container is not allowed: it is hidden in profile %q", src, c.profile)
	}
	for _, inner := range c.policy.Mounts {
		if p := c.resolve(path.Clean(inner.Path)); inner.Hidden && within(p, resolved) {
			return fmt.Sprintf("binding %s into a container is not allowed: it contains %s, which is hidden in profile %q", src, inner.Path, c.profile)
		}
	}
	if a.write && m.ReadOnly {
		return fmt.Sprintf("binding %s writable is not allowed: it is read-only in profile %q; bind it read-only (:ro), or set mode = \"write\" on its [[mounts]] entry", src, c.profile)
	}
	if a.write && a.nonRecursive {
		for _, inner := range c.policy.Mounts {
			p := c.resolve(path.Clean(inner.Path))
			if inner.ReadOnly && p != resolved && within(p, resolved) {
				return fmt.Sprintf("a non-recursive writable bind of %s is not allowed: it would uncover %s, which is read-only in profile %q; use a recursive bind (rbind)", src, inner.Path, c.profile)
			}
		}
	}
	return ""
}

func (c checker) mountFor(p string) (Mount, bool) {
	var best Mount
	bestLen := -1
	for _, m := range c.policy.Mounts {
		if !path.IsAbs(m.Path) {
			continue
		}
		mp := c.resolve(path.Clean(m.Path))
		if within(p, mp) && len(mp) > bestLen {
			best, bestLen = m, len(mp)
		}
	}
	return best, bestLen >= 0
}

func (c checker) resolve(p string) string {
	if c.resolver == nil {
		return p
	}
	var rest []string
	cur := p
	for {
		r, err := c.resolver.EvalSymlinks(cur)
		if err == nil {
			return path.Join(append([]string{r}, rest...)...)
		}
		if cur == "/" {
			return p
		}
		rest = append([]string{path.Base(cur)}, rest...)
		cur = path.Dir(cur)
	}
}

func within(p, base string) bool {
	return base == "/" || p == base || strings.HasPrefix(p, base+"/")
}

func escapes(rel string) bool {
	const anchor = "/anchor"
	return !within(path.Join(anchor, rel), anchor)
}

var errNotBind = errors.New("not a bind")

type bindSpec struct {
	source  string
	options []string
}

func parseBind(s string) (bindSpec, error) {
	parts := strings.Split(s, ":")
	if len(parts) < 2 {
		return bindSpec{}, errNotBind
	}
	b := bindSpec{source: parts[0]}
	if len(parts) > 2 {
		b.options = strings.Split(strings.Join(parts[2:], ":"), ",")
	}
	return b, nil
}

func (c checker) bindArgument(s string) string {
	b, err := parseBind(s)
	if err != nil {
		return ""
	}
	if !strings.HasPrefix(b.source, "/") {
		if volumeName.MatchString(b.source) {
			return ""
		}
		return fmt.Sprintf("bind source %q is neither an absolute path nor a volume name", b.source)
	}
	a, reason := bindAccess(b.options)
	if reason != "" {
		return reason
	}
	return c.bindSource(b.source, a)
}

var bareMountOptions = map[string]bool{
	"ro": true, "rw": true, "bind": true, "rbind": true, "O": true, "U": true,
	"z": true, "Z": true, "copy": true, "nocopy": true, "idmap": true,
	"shared": true, "rshared": true, "slave": true, "rslave": true,
	"private": true, "rprivate": true, "unbindable": true, "runbindable": true,
	"nosuid": true, "suid": true, "nodev": true, "dev": true,
	"noexec": true, "exec": true, "sync": true, "async": true,
	"dirsync": true, "noatime": true, "atime": true, "relatime": true,
	"norelatime": true, "strictatime": true, "nostrictatime": true,
	"nodiratime": true, "diratime": true, "delegated": true, "cached": true,
	"consistent": true, "rro": true, "no-dereference": true,
}

func checkMountOption(o string) string {
	key, value, keyed := strings.Cut(o, "=")
	switch {
	case !keyed && bareMountOptions[o]:
		return ""
	case keyed && key == "relabel" && (value == "shared" || value == "private"):
		return ""
	case key == "upperdir" || key == "workdir":
		return fmt.Sprintf("overlay option %q is not allowed: it names a host directory", key)
	}
	return fmt.Sprintf("mount option %q is not allowed: use only the options doriath knows, such as ro, rw, rbind, z and Z", o)
}

func bindAccess(options []string) (access, string) {
	readOnly, overlay, chown, nonRecursive := false, false, false, false
	for _, o := range options {
		if reason := checkMountOption(o); reason != "" {
			return access{}, reason
		}
		switch o {
		case "ro":
			readOnly = true
		case "O":
			overlay = true
		case "U":
			chown = true
		case "bind":
			nonRecursive = true
		case "rbind":
			nonRecursive = false
		}
	}
	return access{write: chown || (!readOnly && !overlay), nonRecursive: nonRecursive}, ""
}
