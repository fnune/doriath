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
	// Link reports whether the path itself is a symlink.
	Link(path string) bool
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
	homeShowsThrough := !slices.ContainsFunc(s.Tmpfs, func(root string) bool { return within(opts.Home, root) })
	if homeShowsThrough && host.Kind(opts.Home) == "dir" {
		s.Tmpfs = append(s.Tmpfs, opts.Home)
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

	binds, missing, errs := mountBinds(p, layout, host)
	for _, m := range missing {
		errs = append(errs, fmt.Errorf("%s is missing: girdle creates it before the session so that the agent cannot", m.Path))
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
	sources := make([]string, len(binds))
	for i, b := range binds {
		sources[i] = b.Source
	}
	if err := checkLinks(sources, writableSources(binds), host); err != nil {
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

// Placeholder is a control path of git or jj that is missing in a store the
// jail can write. girdle creates it before the session and the jail binds it
// read-only, because the agent could otherwise create it, and git or jj on
// the host would run what it names.
type Placeholder struct {
	Path string
	Dir  bool
	// Content is what a file holds. An empty file is a valid config or
	// alternates file, but git refuses an empty commondir.
	Content string
}

// Placeholders lists the control paths that girdle creates before the
// session.
func Placeholders(p *profile.Profile, host Host) []Placeholder {
	_, missing, _ := mountBinds(p, Layout{}, host)
	return missing
}

// Guards lists the paths inside the profile's writable mounts that the jail
// binds read-only, such as each repository's .git/config.
func Guards(p *profile.Profile, host Host) []string {
	binds, _, _ := mountBinds(p, Layout{}, host)
	var out []string
	for _, b := range binds {
		if b.ReadOnly {
			out = append(out, b.Source)
		}
	}
	return out
}

func mountBinds(p *profile.Profile, layout Layout, host Host) ([]Bind, []Placeholder, []error) {
	var errs []error
	g := &guards{host: host}
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
			g.binds = append(g.binds, Bind{Source: source, Dest: m.Path, ReadOnly: true})
		case profile.ModeWrite:
			g.binds = append(g.binds, Bind{Source: m.Path, Dest: m.Path})
			for _, repo := range Repositories(m.Path, host) {
				g.git(repo, repo)
				g.jj(repo)
			}
		default:
			g.binds = append(g.binds, Bind{Source: m.Path, Dest: m.Path, ReadOnly: true})
			if p.VCSStore {
				for _, repo := range Repositories(m.Path, host) {
					g.store(repo)
				}
			}
		}
	}
	return g.binds, g.missing, errs
}

type guards struct {
	host    Host
	binds   []Bind
	missing []Placeholder
}

func (g *guards) guard(src, dest string, hold *Placeholder) {
	switch {
	case g.host.Kind(src) != "":
		g.binds = append(g.binds, Bind{Source: src, Dest: dest, ReadOnly: true})
	case hold != nil:
		g.missing = append(g.missing, Placeholder{Path: src, Dir: hold.Dir, Content: hold.Content})
	}
}

func (g *guards) writable(path string) {
	if g.host.Kind(path) == "dir" {
		g.binds = append(g.binds, Bind{Source: path, Dest: path})
	}
}

func (g *guards) git(src, dest string) {
	srcGit, destGit := filepath.Join(src, ".git"), filepath.Join(dest, ".git")
	if filepath.Base(src) == ".git" {
		srcGit, destGit = src, dest
	}
	switch g.host.Kind(srcGit) {
	case "file":
		g.guard(srcGit, destGit, nil)
	case "dir":
		g.gitDir(srcGit, destGit, 0)
	}
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
			if sub := filepath.Join(dir, name); host.Kind(sub) == "dir" && !host.Link(sub) {
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
var jjControlFiles = map[string]*Placeholder{"config.toml": {}, "store/git_target": nil, "store/type": nil}

func (g *guards) jj(repo string) {
	jjRepo := filepath.Join(repo, ".jj", "repo")
	switch g.host.Kind(jjRepo) {
	case "file":
		workspacePointer := jjRepo
		g.guard(workspacePointer, workspacePointer, nil)
		return
	case "dir":
	default:
		return
	}
	for _, name := range slices.Sorted(maps.Keys(jjControlFiles)) {
		p := filepath.Join(jjRepo, name)
		g.guard(p, p, jjControlFiles[name])
	}
	if s := filepath.Join(jjRepo, "store", "git"); g.host.Kind(s) == "dir" {
		g.gitDir(s, s, 0)
	}
}

// store makes a repository's store writable inside a read-only mount.
// The control directories themselves stay read-only, so no control file can
// appear in them; only their data subdirectories become writable.
func (g *guards) store(repo string) {
	switch {
	case filepath.Base(repo) == ".git":
		g.gitStore(repo, 0)
		return
	case isJJRepo(repo):
		g.jjRepoStore(repo)
		return
	}
	if git := filepath.Join(repo, ".git"); g.host.Kind(git) == "dir" {
		g.gitStore(git, 0)
	}
	g.writable(filepath.Join(repo, ".jj", "working_copy"))
	if jjRepo := filepath.Join(repo, ".jj", "repo"); g.host.Kind(jjRepo) == "dir" {
		g.jjRepoStore(jjRepo)
	}
}

// isJJRepo reports whether dir is a jj repository directory itself, as
// mounted for a secondary workspace whose .jj/repo points at it.
func isJJRepo(dir string) bool {
	return filepath.Base(dir) == "repo" && filepath.Base(filepath.Dir(dir)) == ".jj"
}

func (g *guards) jjRepoStore(jjRepo string) {
	for _, name := range jjRepoData {
		g.writable(filepath.Join(jjRepo, name))
	}
	for _, name := range JJLockFiles {
		if p := filepath.Join(jjRepo, name); g.host.Kind(p) == "file" {
			g.binds = append(g.binds, Bind{Source: p, Dest: p})
		}
	}
	if s := filepath.Join(jjRepo, "store", "git"); g.host.Kind(s) == "dir" {
		g.gitStore(s, 0)
	}
}

var (
	gitStoreData = []string{"objects", "refs", "logs", "worktrees", "lfs"}
	jjRepoData   = []string{"index", "op_heads", "op_store", "submodule_store", "workspace_store", "store/extra"}
	// JJLockFiles are locks jj takes in .jj/repo itself. jj keeps the files
	// and only locks them, so girdle creates them before the session.
	JJLockFiles = []string{"git_import_export.lock"}
	// worktreeControlFiles, in a worktree's admin directory, decide which
	// repository and config git uses in that worktree.
	worktreeControlFiles = map[string]*Placeholder{"commondir": nil, "gitdir": nil, "config.worktree": {}}
)

func (g *guards) gitStore(gitDir string, depth int) {
	for _, name := range gitStoreData {
		g.writable(filepath.Join(gitDir, name))
	}
	if p := filepath.Join(gitDir, "objects", "info", "alternates"); g.host.Kind(p) == "file" {
		g.binds = append(g.binds, Bind{Source: p, Dest: p, ReadOnly: true})
	}
	g.packs(gitDir)
	g.worktrees(gitDir)
	if depth >= vcs.MaxSubmoduleDepth {
		return
	}
	for _, sub := range vcs.ModuleStores(filepath.Join(gitDir, "modules"), g.host) {
		g.gitStore(sub, depth+1)
	}
}

func (g *guards) worktrees(gitDir string) {
	worktrees := filepath.Join(gitDir, "worktrees")
	for _, name := range g.host.Entries(worktrees) {
		for _, file := range slices.Sorted(maps.Keys(worktreeControlFiles)) {
			p := filepath.Join(worktrees, name, file)
			g.guard(p, p, worktreeControlFiles[file])
		}
	}
}

// GitControlFiles are the entries of a .git directory that decide what git
// runs or which config it reads.
var GitControlFiles = []string{"config", "config.worktree", "commondir", "hooks", "info", "objects/info/alternates"}

var gitHolds = map[string]*Placeholder{
	"config.worktree":         {},
	"commondir":               {Content: ".\n"}, // git refuses an empty one; "." names .git itself
	"hooks":                   {Dir: true},
	"info":                    {Dir: true},
	"objects/info/alternates": {},
}

func (g *guards) gitDir(srcGit, destGit string, depth int) {
	for _, name := range GitControlFiles {
		g.guard(filepath.Join(srcGit, name), filepath.Join(destGit, name), gitHolds[name])
	}
	g.packs(srcGit)
	g.worktrees(srcGit)
	if depth >= vcs.MaxSubmoduleDepth {
		return
	}
	modules := filepath.Join(srcGit, "modules")
	var subs []string
	for _, name := range g.host.Entries(modules) {
		if sub := filepath.Join(modules, name); g.host.Kind(sub) == "dir" {
			subs = append(subs, sub)
		}
	}
	for _, sub := range vcs.ModuleStores(modules, g.host) {
		if !slices.Contains(subs, sub) {
			subs = append(subs, sub)
		}
	}
	for _, sub := range subs {
		rel, _ := filepath.Rel(modules, sub)
		g.gitDir(sub, filepath.Join(destGit, "modules", rel), depth+1)
	}
}

// packs bind each existing pack file read-only. Packs hold nearly all
// of a repository's history, and the files belong to you, so an agent could
// chmod one and overwrite it in place, which no backup by hardlink survives.
// New packs stay writable; git gc in the jail cannot drop the old ones.
func (g *guards) packs(gitDir string) {
	dir := filepath.Join(gitDir, "objects", "pack")
	for _, name := range g.host.Entries(dir) {
		if p := filepath.Join(dir, name); g.host.Kind(p) == "file" {
			g.binds = append(g.binds, Bind{Source: p, Dest: p, ReadOnly: true})
		}
	}
}

// CheckLinks refuses paths that girdle creates or binds before the session
// when they lead through a symlink in a directory the jail can write.
func CheckLinks(p *profile.Profile, host Host, paths ...string) error {
	binds, _, _ := mountBinds(p, Layout{}, host)
	return checkLinks(paths, writableSources(binds), host)
}

func checkLinks(paths, roots []string, host Host) error {
	for _, path := range paths {
		for p := path; p != "/" && p != "."; p = filepath.Dir(p) {
			if !host.Link(p) {
				continue
			}
			for _, root := range roots {
				if p != root && within(p, root) {
					return fmt.Errorf("%s goes through the symlink %s, inside %s, which the jail can write: remove the link, or mount the directory it points to", path, p, root)
				}
			}
		}
	}
	return nil
}

func writableSources(binds []Bind) []string {
	var out []string
	for _, b := range binds {
		if !b.ReadOnly && !b.Device {
			out = append(out, b.Source)
		}
	}
	return out
}

func within(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
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
