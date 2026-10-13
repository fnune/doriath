// Package jail turns a profile into a bubblewrap invocation. The jail starts
// from a read-only view of the system with the home directory, /run and
// /tmp replaced, then adds back only what the profile names.
package jail

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/fnune/girdle/internal/profile"
)

// Paths inside the jail where girdle puts its own files and sockets.
const (
	Dir       = "/run/girdle"
	ExePath   = "/run/girdle-bin/girdle"
	ProxyPort = 3128
)

func InJail(name string) string { return filepath.Join(Dir, name) }

// Layout is where the session keeps its files on the host.
type Layout struct {
	// JailDir holds the sockets and generated files, bound read-only at Dir.
	JailDir string
	// CacheRoot backs the profile's cache mounts.
	CacheRoot string
	// Tmp backs /tmp, so scratch files survive a resumed session.
	Tmp string
	Exe string
}

func CacheSource(root, path, home string) string {
	rel, err := filepath.Rel(home, path)
	if err != nil {
		rel = strings.TrimPrefix(path, "/")
	}
	return filepath.Join(root, "home", rel)
}

// Host answers questions about the host filesystem.
type Host interface {
	// Kind returns "dir", "file", "other" or "" when the path does not exist.
	Kind(path string) string
}

type Bind struct {
	Source   string
	Dest     string
	ReadOnly bool
	Device   bool
}

type Spec struct {
	// SkipUserNS is for a process that already runs as root in its own user
	// namespace, such as the podman service.
	SkipUserNS bool
	// SkipNetNS keeps the caller's network namespace, for an agent that joins
	// the session's shared namespace.
	SkipNetNS bool
	// InfoFD is a file descriptor for bubblewrap's JSON status, or 0.
	InfoFD   int
	Hostname string
	UID      int
	Home     string
	Tmpfs    []string
	Dirs     []string
	Binds    []Bind
	Env      map[string]string
	Cwd      string
	Command  []string
}

type Options struct {
	UID     int
	Home    string
	Cwd     string
	Command []string
	// HostEnv is the environment girdle runs in. Only variables the profile
	// passes reach the jail.
	HostEnv map[string]string
	// ExtraEnv is set by girdle itself: proxy, sockets, CA bundle and so on.
	ExtraEnv map[string]string
	// ExtraBinds come from adapters, for example the agent's own state.
	ExtraBinds []Bind
	SkipUserNS bool
	SkipNetNS  bool
	InfoFD     int
	// JailDirWritable lets a helper such as the podman service create its
	// socket in the girdle directory.
	JailDirWritable bool
}

var hiddenRoots = []string{"/home", "/root", "/run", "/tmp", "/var/tmp", "/mnt", "/media", "/srv"}

func Plan(p *profile.Profile, layout Layout, opts Options, host Host) (Spec, error) {
	if !filepath.IsAbs(opts.Home) || !filepath.IsAbs(opts.Cwd) {
		return Spec{}, errors.New("home and working directory must be absolute")
	}
	if len(opts.Command) == 0 {
		return Spec{}, errors.New("no command to run")
	}
	s := Spec{
		SkipUserNS: opts.SkipUserNS,
		SkipNetNS:  opts.SkipNetNS,
		InfoFD:     opts.InfoFD,
		Hostname:   "girdle-" + p.Name,
		UID:        opts.UID,
		Home:       opts.Home,
		Env:        map[string]string{},
		Cwd:        opts.Cwd,
		Command:    opts.Command,
	}
	for _, root := range hiddenRoots {
		if host.Kind(root) == "dir" {
			s.Tmpfs = append(s.Tmpfs, root)
		}
	}
	runtime := filepath.Join("/run/user", strconv.Itoa(opts.UID))
	s.Dirs = append(s.Dirs, opts.Home, runtime)

	var errs []error
	var binds []Bind
	for _, m := range p.Mounts {
		kind := host.Kind(m.Path)
		if kind == "" {
			if m.Optional {
				continue
			}
			errs = append(errs, fmt.Errorf("mount %s does not exist: create it or mark it optional", m.Path))
			continue
		}
		binds = append(binds, Bind{Source: m.Path, Dest: m.Path, ReadOnly: m.Mode == profile.ModeReadOnly})
		if m.Mode == profile.ModeReadWrite {
			binds = append(binds, gitGuards(m.Path, host)...)
		}
	}
	for _, c := range p.Caches {
		binds = append(binds, Bind{Source: CacheSource(layout.CacheRoot, c.Path, opts.Home), Dest: c.Path})
	}
	for _, d := range p.Devices {
		if host.Kind(d) == "" {
			errs = append(errs, fmt.Errorf("device %s does not exist", d))
			continue
		}
		binds = append(binds, Bind{Source: d, Dest: d, Device: true})
	}
	binds = append(binds, opts.ExtraBinds...)
	binds = append(binds,
		Bind{Source: layout.Tmp, Dest: "/tmp"},
		Bind{Source: layout.JailDir, Dest: Dir, ReadOnly: !opts.JailDirWritable},
		Bind{Source: layout.Exe, Dest: ExePath, ReadOnly: true},
	)
	if err := checkCwd(opts.Cwd, binds); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return Spec{}, err
	}
	// Parents must be mounted before children, or a parent bind would hide
	// the child. A stable sort keeps the declared order among equals.
	sort.SliceStable(binds, func(i, j int) bool { return depth(binds[i].Dest) < depth(binds[j].Dest) })
	s.Binds = binds

	for _, k := range p.Env.Pass {
		if v, ok := opts.HostEnv[k]; ok {
			s.Env[k] = v
		}
	}
	for k, v := range p.Env.Set {
		s.Env[k] = v
	}
	s.Env["HOME"] = opts.Home
	s.Env["XDG_RUNTIME_DIR"] = runtime
	s.Env["GIRDLE_PROFILE"] = p.Name
	for k, v := range opts.ExtraEnv {
		s.Env[k] = v
	}
	return s, nil
}

// gitGuards keeps a repo's config and hooks read-only. git outside the jail
// runs hooks and commands named in the config (core.fsmonitor,
// core.hooksPath and others), so a writable copy would let the agent run code
// on the desktop.
func gitGuards(root string, host Host) []Bind {
	gitDir := filepath.Join(root, ".git")
	if host.Kind(gitDir) != "dir" {
		return nil
	}
	var binds []Bind
	for _, name := range []string{"config", "hooks", "info"} {
		p := filepath.Join(gitDir, name)
		if host.Kind(p) != "" {
			binds = append(binds, Bind{Source: p, Dest: p, ReadOnly: true})
		}
	}
	return binds
}

func checkCwd(cwd string, binds []Bind) error {
	for _, b := range binds {
		if !b.Device && (cwd == b.Dest || strings.HasPrefix(cwd, b.Dest+"/")) {
			return nil
		}
	}
	return fmt.Errorf("working directory %s is not inside any mount of the profile", cwd)
}

func depth(p string) int {
	if p == "/" {
		return 0
	}
	return strings.Count(filepath.Clean(p), "/")
}

// Args returns the bubblewrap arguments, without the bwrap binary itself.
// Option order matters: bubblewrap applies mounts in sequence, so the root
// bind comes first and /proc after it.
func (s Spec) Args() []string {
	var args []string
	if !s.SkipUserNS {
		args = append(args, "--unshare-user")
	}
	if !s.SkipNetNS {
		args = append(args, "--unshare-net")
	}
	if s.InfoFD > 0 {
		args = append(args, "--info-fd", strconv.Itoa(s.InfoFD))
	}
	args = append(args,
		"--unshare-ipc",
		"--unshare-pid",
		"--unshare-uts",
		"--unshare-cgroup-try",
		"--die-with-parent",
		"--hostname", s.Hostname,
		"--ro-bind", "/", "/",
		"--dev", "/dev",
		"--proc", "/proc",
	)
	for _, t := range s.Tmpfs {
		args = append(args, "--tmpfs", t)
	}
	for _, d := range s.Dirs {
		args = append(args, "--perms", "0700", "--dir", d)
	}
	for _, b := range s.Binds {
		switch {
		case b.Device:
			args = append(args, "--dev-bind", b.Source, b.Dest)
		case b.ReadOnly:
			args = append(args, "--ro-bind", b.Source, b.Dest)
		default:
			args = append(args, "--bind", b.Source, b.Dest)
		}
	}
	args = append(args, "--clearenv")
	keys := make([]string, 0, len(s.Env))
	for k := range s.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "--setenv", k, s.Env[k])
	}
	args = append(args, "--chdir", s.Cwd, "--")
	return append(args, s.Command...)
}
