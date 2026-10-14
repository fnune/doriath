// Package jail turns a profile into a bubblewrap invocation. The jail starts
// from a read-only view of the system with the home directory, /run and
// /tmp replaced, then adds back only what the profile names.
package jail

import (
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/fnune/girdle/internal/profile"
	"github.com/fnune/girdle/internal/vcs"
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

// EmptyDir is the empty directory, inside the jail directory, that hidden
// directories show.
func (l Layout) EmptyDir() string { return filepath.Join(l.JailDir, "empty") }

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
	// Entries lists the names in a directory, or nothing if it cannot.
	Entries(dir string) []string
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
	InfoFD int
	// SeccompFD is a file descriptor with a seccomp program, or 0.
	SeccompFD int
	// SetIDs maps the jail's user and group to UID and GID explicitly, for a
	// bubblewrap that starts as root inside another user namespace.
	SetIDs   bool
	GID      int
	Hostname string
	UID      int
	Home     string
	Tmpfs    []string
	Dirs     []string
	// Symlinks maps a path in the jail to the target it points at.
	Symlinks map[string]string
	Binds    []Bind
	Env      map[string]string
	Cwd      string
	Command  []string
	// Notes are advice for the person who starts the session. They never
	// change the jail.
	Notes []string
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
	SeccompFD  int
	SetIDs     bool
	GID        int
	// JailDirWritable lets a helper such as the podman service create its
	// socket in the girdle directory.
	JailDirWritable bool
}

const nixDaemonDir = "/nix/var/nix/daemon-socket"

var hiddenRoots = []string{"/home", "/root", "/run", "/tmp", "/var", "/var/tmp", "/opt", "/mnt", "/media", "/srv", "/boot"}

var varLinks = map[string]string{"/var/run": "../run", "/var/lock": "../run/lock"}

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
		SeccompFD:  opts.SeccompFD,
		SetIDs:     opts.SetIDs,
		GID:        opts.GID,
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
	for link, target := range varLinks {
		if host.Kind("/var") == "dir" {
			if s.Symlinks == nil {
				s.Symlinks = map[string]string{}
			}
			s.Symlinks[link] = target
		}
	}
	if !p.NixDaemon && host.Kind(nixDaemonDir) == "dir" {
		s.Tmpfs = append(s.Tmpfs, nixDaemonDir)
	}
	runtime := filepath.Join("/run/user", strconv.Itoa(opts.UID))
	s.Dirs = append(s.Dirs, opts.Home, runtime)

	var errs []error
	var binds []Bind
	for _, m := range p.Mounts {
		kind := host.Kind(m.Path)
		if kind == "" {
			if m.Optional || m.Mode == profile.ModeHide {
				continue
			}
			errs = append(errs, fmt.Errorf("mount %s does not exist: create it or mark it optional", m.Path))
			continue
		}
		switch m.Mode {
		case profile.ModeHide:
			source := layout.EmptyDir()
			if kind != "dir" {
				source = "/dev/null"
			}
			binds = append(binds, Bind{Source: source, Dest: m.Path, ReadOnly: true})
		case profile.ModeWrite:
			binds = append(binds, Bind{Source: m.Path, Dest: m.Path})
			for _, repo := range Repositories(m.Path, host) {
				binds = append(binds, gitGuards(repo, repo, host)...)
				binds = append(binds, jjGuards(repo, host)...)
			}
		default:
			binds = append(binds, Bind{Source: m.Path, Dest: m.Path, ReadOnly: true})
			if p.VCSStore {
				for _, repo := range Repositories(m.Path, host) {
					binds = append(binds, storeBinds(repo, host)...)
				}
			}
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
	mountParentsBeforeChildren(binds)
	s.Binds = binds

	for _, k := range p.Env.Pass {
		if v, ok := opts.HostEnv[k]; ok {
			s.Env[k] = v
		}
	}
	for k, v := range p.Env.Set {
		s.Env[k] = v
	}
	if len(p.Env.PathPrepend) > 0 {
		path := strings.Join(p.Env.PathPrepend, ":")
		if rest := s.Env["PATH"]; rest != "" {
			path += ":" + rest
		}
		s.Env["PATH"] = path
	}
	s.Env["HOME"] = opts.Home
	s.Env["XDG_RUNTIME_DIR"] = runtime
	s.Env["GIRDLE_PROFILE"] = p.Name
	for k, v := range opts.ExtraEnv {
		s.Env[k] = v
	}
	return s, nil
}

func gitGuards(src, dest string, host Host) []Bind {
	srcGit, destGit := filepath.Join(src, ".git"), filepath.Join(dest, ".git")
	if filepath.Base(src) == ".git" {
		srcGit, destGit = src, dest
	}
	switch host.Kind(srcGit) {
	case "file":
		return []Bind{{Source: srcGit, Dest: destGit, ReadOnly: true}}
	case "dir":
		return gitDirGuards(srcGit, destGit, host, 0)
	}
	return nil
}

// Repositories lists the git and jj repositories at or below root, a few levels
// deep.
func Repositories(root string, host Host) []string {
	var out []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if host.Kind(filepath.Join(dir, ".git")) != "" || host.Kind(filepath.Join(dir, ".jj")) != "" || filepath.Base(dir) == ".git" || isJJRepo(dir) {
			out = append(out, dir)
		}
		if depth == repositoryDepth {
			return
		}
		for _, name := range host.Entries(dir) {
			if skipWalk[name] {
				continue
			}
			if sub := filepath.Join(dir, name); host.Kind(sub) == "dir" {
				walk(sub, depth+1)
			}
		}
	}
	walk(root, 0)
	return out
}

const repositoryDepth = 3

var skipWalk = map[string]bool{".git": true, ".jj": true, "node_modules": true, ".cache": true, "vendor": true, "target": true}

// jjControlFiles decide what jj runs or which git store it uses.
var jjControlFiles = []string{"config.toml", "store/git_target", "store/type"}

func jjGuards(repo string, host Host) []Bind {
	var binds []Bind
	for _, name := range jjControlFiles {
		if p := filepath.Join(repo, ".jj", "repo", name); host.Kind(p) != "" {
			binds = append(binds, Bind{Source: p, Dest: p, ReadOnly: true})
		}
	}
	if g := filepath.Join(repo, ".jj", "repo", "store", "git"); host.Kind(g) == "dir" {
		binds = append(binds, gitDirGuards(g, g, host, 0)...)
	}
	return binds
}

// storeBinds make a repository's store writable inside a read-only mount.
// The control directories themselves stay read-only, so no control file can
// appear in them; only their data subdirectories become writable.
func storeBinds(repo string, host Host) []Bind {
	switch {
	case filepath.Base(repo) == ".git":
		return gitStore(repo, host, 0)
	case isJJRepo(repo):
		return jjRepoStore(repo, host)
	}
	var binds []Bind
	if git := filepath.Join(repo, ".git"); host.Kind(git) == "dir" {
		binds = append(binds, gitStore(git, host, 0)...)
	}
	binds = append(binds, writable(host, filepath.Join(repo, ".jj", "working_copy"))...)
	if jjRepo := filepath.Join(repo, ".jj", "repo"); host.Kind(jjRepo) == "dir" {
		binds = append(binds, jjRepoStore(jjRepo, host)...)
	}
	return binds
}

// isJJRepo reports whether dir is a jj repository directory itself, as
// mounted for a secondary workspace whose .jj/repo points at it.
func isJJRepo(dir string) bool {
	return filepath.Base(dir) == "repo" && filepath.Base(filepath.Dir(dir)) == ".jj"
}

func jjRepoStore(jjRepo string, host Host) []Bind {
	var binds []Bind
	for _, name := range jjRepoData {
		binds = append(binds, writable(host, filepath.Join(jjRepo, name))...)
	}
	for _, name := range JJLockFiles {
		if p := filepath.Join(jjRepo, name); host.Kind(p) == "file" {
			binds = append(binds, Bind{Source: p, Dest: p})
		}
	}
	if g := filepath.Join(jjRepo, "store", "git"); host.Kind(g) == "dir" {
		binds = append(binds, gitStore(g, host, 0)...)
	}
	return binds
}

var (
	gitStoreData = []string{"objects", "refs", "logs", "worktrees", "lfs"}
	jjRepoData   = []string{"index", "op_heads", "op_store", "submodule_store", "workspace_store", "store/extra"}
	// JJLockFiles are locks jj takes in .jj/repo itself. jj keeps the files
	// and only locks them, so girdle creates them before the session.
	JJLockFiles = []string{"git_import_export.lock"}
	// worktreeControlFiles, in a worktree's admin directory, decide which
	// repository and config git uses in that worktree.
	worktreeControlFiles = []string{"commondir", "gitdir", "config.worktree"}
)

func gitStore(gitDir string, host Host, depth int) []Bind {
	var binds []Bind
	for _, name := range gitStoreData {
		binds = append(binds, writable(host, filepath.Join(gitDir, name))...)
	}
	if p := filepath.Join(gitDir, "objects", "info", "alternates"); host.Kind(p) == "file" {
		binds = append(binds, Bind{Source: p, Dest: p, ReadOnly: true})
	}
	binds = append(binds, packGuards(gitDir, host)...)
	binds = append(binds, worktreeGuards(gitDir, host)...)
	if depth >= vcs.MaxSubmoduleDepth {
		return binds
	}
	modules := filepath.Join(gitDir, "modules")
	for _, name := range host.Entries(modules) {
		if sub := filepath.Join(modules, name); host.Kind(sub) == "dir" {
			binds = append(binds, gitStore(sub, host, depth+1)...)
		}
	}
	return binds
}

func worktreeGuards(gitDir string, host Host) []Bind {
	var binds []Bind
	worktrees := filepath.Join(gitDir, "worktrees")
	for _, name := range host.Entries(worktrees) {
		for _, file := range worktreeControlFiles {
			if p := filepath.Join(worktrees, name, file); host.Kind(p) != "" {
				binds = append(binds, Bind{Source: p, Dest: p, ReadOnly: true})
			}
		}
	}
	return binds
}

func writable(host Host, path string) []Bind {
	if host.Kind(path) != "dir" {
		return nil
	}
	return []Bind{{Source: path, Dest: path}}
}

// GitControlFiles are the entries of a .git directory that decide what git
// runs or which config it reads.
var GitControlFiles = []string{"config", "config.worktree", "commondir", "hooks", "info", "objects/info/alternates"}

func gitDirGuards(srcGit, destGit string, host Host, depth int) []Bind {
	var binds []Bind
	for _, name := range GitControlFiles {
		if p := filepath.Join(srcGit, name); host.Kind(p) != "" {
			binds = append(binds, Bind{Source: p, Dest: filepath.Join(destGit, name), ReadOnly: true})
		}
	}
	binds = append(binds, packGuards(srcGit, host)...)
	binds = append(binds, worktreeGuards(srcGit, host)...)
	if depth >= vcs.MaxSubmoduleDepth {
		return binds
	}
	modules := filepath.Join(srcGit, "modules")
	for _, name := range host.Entries(modules) {
		if sub := filepath.Join(modules, name); host.Kind(sub) == "dir" {
			binds = append(binds, gitDirGuards(sub, filepath.Join(destGit, "modules", name), host, depth+1)...)
		}
	}
	return binds
}

// packGuards bind each existing pack file read-only. Packs hold nearly all
// of a repository's history, and the files belong to you, so an agent could
// chmod one and overwrite it in place, which no backup by hardlink survives.
// New packs stay writable; git gc in the jail cannot drop the old ones.
func packGuards(gitDir string, host Host) []Bind {
	var binds []Bind
	dir := filepath.Join(gitDir, "objects", "pack")
	for _, name := range host.Entries(dir) {
		if p := filepath.Join(dir, name); host.Kind(p) == "file" {
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
	if s.SetIDs {
		args = append(args, "--uid", strconv.Itoa(s.UID), "--gid", strconv.Itoa(s.GID))
	}
	if s.InfoFD > 0 {
		args = append(args, "--info-fd", strconv.Itoa(s.InfoFD))
	}
	if s.SeccompFD > 0 {
		args = append(args, "--seccomp", strconv.Itoa(s.SeccompFD))
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
	for _, link := range slices.Sorted(maps.Keys(s.Symlinks)) {
		args = append(args, "--symlink", s.Symlinks[link], link)
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

func mountParentsBeforeChildren(binds []Bind) {
	sort.SliceStable(binds, func(i, j int) bool { return depth(binds[i].Dest) < depth(binds[j].Dest) })
}
