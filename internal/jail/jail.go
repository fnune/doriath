// Package jail turns a profile into a bubblewrap invocation. The jail starts
// from a read-only view of the system with the home directory, /run and
// /tmp replaced, then adds back only what the profile names.
package jail

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/vcs"
	"golang.org/x/sys/unix"
)

const (
	Dir       = "/run/doriath"
	ExePath   = "/run/doriath-bin/doriath"
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
	// Home backs the home directory, so that what the agent writes outside
	// the mounts and caches stays on disk instead of in memory.
	Home string
	Exe  string
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
	// Resolve returns the path with every symlink followed, or "" when it
	// leads nowhere.
	Resolve(path string) string
	// List lists a directory's entries with their type, from the listing
	// itself, or nothing if it cannot.
	List(dir string) []Entry
}

// Entry is a directory entry. Dir is false for a symlink to a directory.
type Entry struct {
	Name string
	Dir  bool
}

type Bind struct {
	Source   string
	Dest     string
	ReadOnly bool
	Device   bool
	// Try skips the bind when Source is gone by the time the jail starts,
	// for a file that a program on the host may delete at any time.
	Try bool
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
	// EtcOverlay is a host directory whose files appear in /etc, read-only.
	// A bind cannot add a file there, because the root bind is read-only.
	EtcOverlay string
	Dirs       []string
	// Symlinks maps a path in the jail to the target it points at.
	Symlinks map[string]string
	// Links are guarded paths that are symlinks inside a writable mount.
	// bubblewrap cannot mount onto a symlink, so the session keeps each one
	// pointing where it pointed when the session started.
	Links   []string
	Binds   []Bind
	Env     map[string]string
	Cwd     string
	Command []string
	// Notes are advice for the person who starts the session. They never
	// change the jail.
	Notes []string
}

type Options struct {
	UID     int
	Home    string
	Cwd     string
	Command []string
	// HostEnv is the environment doriath runs in. Only variables the profile
	// passes reach the jail.
	HostEnv map[string]string
	// ExtraEnv is set by doriath itself: proxy, sockets, CA bundle and so on.
	ExtraEnv map[string]string
	// PathPrepend puts doriath's own fronts, such as its git, before PATH.
	// A jail without PATH gets none, so that it still finds the system's.
	PathPrepend []string
	// ExtraBinds come from adapters, for example the agent's own state.
	ExtraBinds []Bind
	SkipUserNS bool
	SkipNetNS  bool
	InfoFD     int
	SeccompFD  int
	SetIDs     bool
	GID        int
	// EtcOverlay is a host directory whose files appear in the jail's /etc.
	EtcOverlay string
	// JailDirWritable lets a helper such as the podman service create its
	// socket in the doriath directory.
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
		Hostname:   "doriath-" + p.Label(),
		UID:        opts.UID,
		Home:       opts.Home,
		EtcOverlay: opts.EtcOverlay,
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

	binds, missing, errs := mountBinds(p, layout, host)
	for _, m := range missing {
		errs = append(errs, fmt.Errorf("%s is missing: doriath creates it before the session so that the agent cannot", m.Path))
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
	binds = append(binds, Bind{Source: layout.Home, Dest: opts.Home})
	binds, s.Links, errs = splitGuardedLinks(binds, host, errs)
	if err := errors.Join(errs...); err != nil {
		return Spec{}, err
	}
	sources := make([]string, len(binds))
	for i, b := range binds {
		sources[i] = b.Source
	}
	binds = append(binds, parentPins(binds, host)...)
	sources = make([]string, len(binds))
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
	if path := s.Env["PATH"]; path != "" && len(opts.PathPrepend) > 0 {
		s.Env["PATH"] = strings.Join(opts.PathPrepend, ":") + ":" + path
	}
	s.Env["HOME"] = opts.Home
	s.Env["XDG_RUNTIME_DIR"] = runtime
	s.Env["DORIATH_PROFILE"] = p.Name
	for k, v := range opts.ExtraEnv {
		s.Env[k] = v
	}
	return s, nil
}

// Placeholder is a control path of git or jj that is missing in a store the
// jail can write. doriath creates it before the session and the jail binds it
// read-only, because the agent could otherwise create it, and git or jj on
// the host would run what it names.
type Placeholder struct {
	Path string
	Dir  bool
	// Content is what a file holds. An empty file is a valid config or
	// alternates file, but git refuses an empty commondir.
	Content string
}

// Placeholders lists the control paths that doriath creates before the
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

// GitRoots lists the git stores whose root the jail can write: those of
// repositories in writable mounts, and those that [vcs] store opens.
func GitRoots(p *profile.Profile, host Host) []string {
	g, _ := mountGuards(p, Layout{}, host)
	return g.roots
}

// JJRepos lists the .jj/repo directories of the jj repositories whose
// store the jail can write: those in writable mounts, and those that
// [vcs] store opens.
func JJRepos(p *profile.Profile, host Host) []string {
	g, _ := mountGuards(p, Layout{}, host)
	return slices.Compact(slices.Sorted(slices.Values(g.jjRepos)))
}

func mountBinds(p *profile.Profile, layout Layout, host Host) ([]Bind, []Placeholder, []error) {
	g, errs := mountGuards(p, layout, host)
	return g.binds, g.missing, errs
}

func mountGuards(p *profile.Profile, layout Layout, host Host) (*guards, []error) {
	var errs []error
	g := &guards{host: host}
	for _, m := range p.Mounts {
		kind := host.Kind(m.Path)
		if kind == "" {
			if m.OnMissing() != profile.MissingError {
				continue
			}
			errs = append(errs, fmt.Errorf("mount %s does not exist: create it, or set missing = \"skip\"", m.Path))
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
	g.binds = uniqueBinds(g.binds)
	return g, errs
}

func uniqueBinds(binds []Bind) []Bind {
	seen := map[Bind]bool{}
	out := binds[:0]
	for _, b := range binds {
		if !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	return out
}

type guards struct {
	host    Host
	binds   []Bind
	missing []Placeholder
	roots   []string
	jjRepos []string
	guarded map[[2]string]bool
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
// deep. It reads each directory once and stats nothing it lists: a mount of
// many checkouts holds hundreds of thousands of entries, and with a cold
// cache each stat is a disk read.
func Repositories(root string, host Host) []string {
	var out []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		repo := filepath.Base(dir) == ".git" || isJJRepo(dir)
		var entries []Entry
		if depth < repositoryDepth {
			entries = host.List(dir)
			repo = repo || slices.ContainsFunc(entries, func(e Entry) bool { return e.Name == ".git" || e.Name == ".jj" })
		} else {
			repo = repo || host.Kind(filepath.Join(dir, ".git")) != "" || host.Kind(filepath.Join(dir, ".jj")) != ""
		}
		if repo {
			out = append(out, dir)
		}
		for _, e := range entries {
			if e.Dir && !skipWalk[e.Name] {
				walk(filepath.Join(dir, e.Name), depth+1)
			}
		}
	}
	walk(root, 0)
	return out
}

const repositoryDepth = 3

var skipWalk = map[string]bool{".git": true, ".jj": true, "node_modules": true, ".cache": true, "vendor": true, "target": true}

var jjControlFiles = map[string]*Placeholder{"config.toml": {}, "config-id": nil, "store/git_target": nil, "store/type": nil}

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
	g.jjRepos = append(g.jjRepos, jjRepo)
	for _, name := range slices.Sorted(maps.Keys(jjControlFiles)) {
		p := filepath.Join(jjRepo, name)
		g.guard(p, p, jjControlFiles[name])
	}
	if s := filepath.Join(jjRepo, "store", "git"); g.host.Kind(s) == "dir" {
		g.gitDir(s, s, 0)
	}
}

func (g *guards) store(repo string) {
	switch {
	case filepath.Base(repo) == ".git":
		g.gitStore(repo)
		return
	case isJJRepo(repo):
		g.jjRepoStore(repo)
		return
	}
	if git := filepath.Join(repo, ".git"); g.host.Kind(git) == "dir" {
		g.gitStore(git)
	}
	g.writable(filepath.Join(repo, ".jj", "working_copy"))
	if jjRepo := filepath.Join(repo, ".jj", "repo"); g.host.Kind(jjRepo) == "dir" {
		g.jjRepoStore(jjRepo)
	}
}

func isJJRepo(dir string) bool {
	return filepath.Base(dir) == "repo" && filepath.Base(filepath.Dir(dir)) == ".jj"
}

func (g *guards) jjRepoStore(jjRepo string) {
	g.jjRepos = append(g.jjRepos, jjRepo)
	for _, name := range jjRepoData {
		g.writable(filepath.Join(jjRepo, name))
	}
	for _, name := range jjLockFiles {
		p := filepath.Join(jjRepo, name)
		if g.host.Kind(p) == "file" {
			g.binds = append(g.binds, Bind{Source: p, Dest: p, Try: true})
			continue
		}
		g.missing = append(g.missing, Placeholder{Path: p})
	}
	if s := filepath.Join(jjRepo, "store", "git"); g.host.Kind(s) == "dir" {
		g.gitStore(s)
	}
}

var (
	jjRepoData  = []string{"index", "op_heads", "op_store", "submodule_store", "workspace_store", "store/extra"}
	jjLockFiles = []string{"git_import_export.lock"}

	worktreeControlFiles = map[string]*Placeholder{"commondir": nil, "gitdir": nil, "config.worktree": {}}
)

func (g *guards) gitStore(gitDir string) {
	g.writable(gitDir)
	g.gitDir(gitDir, gitDir, 0)
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
// runs, which config it reads, or how it resolves your next merge.
var GitControlFiles = []string{"config", "config.worktree", "commondir", "hooks", "info", "objects/info/alternates", "rr-cache", "remotes", "branches"}

var gitHolds = map[string]*Placeholder{
	"config.worktree":         {},
	"hooks":                   {Dir: true},
	"info":                    {Dir: true},
	"objects/info/alternates": {},
	"remotes":                 {Dir: true},
	"branches":                {Dir: true},
}

func (g *guards) gitDir(srcGit, destGit string, depth int) {
	if g.guarded == nil {
		g.guarded = map[[2]string]bool{}
	}
	if g.guarded[[2]string{srcGit, destGit}] {
		return
	}
	g.guarded[[2]string{srcGit, destGit}] = true
	g.roots = append(g.roots, srcGit)
	for _, name := range GitControlFiles {
		if name == vcs.Commondir {
			continue
		}
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

func (g *guards) packs(gitDir string) {
	dir := filepath.Join(gitDir, "objects", "pack")
	for _, name := range g.host.Entries(dir) {
		if p := filepath.Join(dir, name); g.host.Kind(p) == "file" {
			g.binds = append(g.binds, Bind{Source: p, Dest: p, ReadOnly: true})
		}
	}
}

// CheckLinks refuses paths that doriath creates or binds before the session
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

func splitGuardedLinks(binds []Bind, host Host, errs []error) ([]Bind, []string, []error) {
	writable := writableSources(binds)
	var kept []Bind
	var links []string
	for _, b := range binds {
		if !b.ReadOnly || b.Device || b.Source != b.Dest || !host.Link(b.Dest) {
			kept = append(kept, b)
			continue
		}
		parent, ok := enclosing(binds, b.Dest)
		if !ok || parent.Source != parent.Dest {
			kept = append(kept, b)
			continue
		}
		if parent.ReadOnly {
			continue
		}
		if err := checkLinkTarget(b.Dest, writable, host); err != nil {
			errs = append(errs, err)
			continue
		}
		links = append(links, b.Dest)
	}
	return kept, links, errs
}

func checkLinkTarget(link string, writable []string, host Host) error {
	target := host.Resolve(link)
	for _, root := range writable {
		if target != "" && within(target, root) {
			return fmt.Errorf("%s points to %s, which the jail can write: the agent could change what %s holds. Point the link outside the writable mounts, or replace it with the file", link, target, filepath.Base(link))
		}
	}
	return nil
}

// GuardsAndLinks splits the read-only paths inside p's mounts into those
// doriath mounts read-only and the symlinks it keeps in place instead.
func GuardsAndLinks(p *profile.Profile, host Host) (guards, links []string, err error) {
	binds, _, _ := mountBinds(p, Layout{}, host)
	kept, links, errs := splitGuardedLinks(binds, host, nil)
	for _, b := range kept {
		if b.ReadOnly {
			guards = append(guards, b.Source)
		}
	}
	return guards, links, errors.Join(errs...)
}

func parentPins(binds []Bind, host Host) []Bind {
	seen := map[string]bool{}
	var pins []Bind
	for _, b := range binds {
		if !b.ReadOnly || b.Device {
			continue
		}
		parent, ok := enclosing(binds, b.Dest)
		if !ok || parent.ReadOnly || parent.Device {
			continue
		}
		for _, dir := range Between(parent.Dest, b.Dest) {
			if seen[dir] {
				continue
			}
			seen[dir] = true
			rel, _ := filepath.Rel(parent.Dest, dir)
			source := filepath.Join(parent.Source, rel)
			if host.Kind(source) == "dir" {
				pins = append(pins, Bind{Source: source, Dest: dir})
			}
		}
	}
	return pins
}

// Between lists the directories strictly between root and path, the
// shallowest first, or nothing when path is not below root.
func Between(root, path string) []string {
	var out []string
	for dir := filepath.Dir(path); dir != root && within(dir, root) && dir != "/"; dir = filepath.Dir(dir) {
		out = append(out, dir)
	}
	slices.Reverse(out)
	return out
}

func enclosing(binds []Bind, path string) (Bind, bool) {
	var best Bind
	found := false
	for _, b := range binds {
		if b.Dest != path && !b.Device && within(path, b.Dest) && (!found || len(b.Dest) > len(best.Dest)) {
			best, found = b, true
		}
	}
	return best, found
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
// ArgsFile holds the arguments for bubblewrap's --args, one after another
// with a NUL after each. A jail that guards many repositories has more
// arguments than one command line takes.
func (s Spec) ArgsFile() (*os.File, error) {
	fd, err := unix.MemfdCreate("doriath-bwrap-args", unix.MFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("hold the bubblewrap arguments: %w", err)
	}
	f := os.NewFile(uintptr(fd), "bwrap-args")
	var b bytes.Buffer
	for _, arg := range s.options() {
		b.WriteString(arg)
		b.WriteByte(0)
	}
	if _, err := f.Write(b.Bytes()); err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func (s Spec) Args() []string {
	return append(append(s.options(), "--"), s.Command...)
}

// ArgsFrom is the command line of a jail whose options bubblewrap reads
// from fd, which ArgsFile holds. The command stays on the command line,
// because bubblewrap takes only options from --args.
func (s Spec) ArgsFrom(fd int) []string {
	return append([]string{"--args", strconv.Itoa(fd), "--"}, s.Command...)
}

func (s Spec) options() []string {
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
	if s.EtcOverlay != "" {
		args = append(args, "--overlay-src", "/etc", "--overlay-src", s.EtcOverlay, "--ro-overlay", "/etc")
	}
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
		case b.Try:
			args = append(args, "--bind-try", b.Source, b.Dest)
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
	return append(args, "--chdir", s.Cwd)
}

func mountParentsBeforeChildren(binds []Bind) {
	sort.SliceStable(binds, func(i, j int) bool { return depth(binds[i].Dest) < depth(binds[j].Dest) })
}
