package jail

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/profile"
)

type fakeHost map[string]string

func (h fakeHost) Kind(p string) string {
	if h[p] == "link" {
		return "dir"
	}
	return h[p]
}

func (h fakeHost) Link(p string) bool { return h[p] == "link" }

func (h fakeHost) Entries(dir string) []string {
	var out []string
	for p := range h {
		if rest, ok := strings.CutPrefix(p, dir+"/"); ok && !strings.Contains(rest, "/") {
			out = append(out, rest)
		}
	}
	return out
}

func (h fakeHost) List(dir string) []Entry {
	var out []Entry
	for _, name := range h.Entries(dir) {
		p := dir + "/" + name
		out = append(out, Entry{Name: name, Dir: h[p] == "dir"})
	}
	return out
}

func held(p *profile.Profile, h fakeHost) fakeHost {
	for _, m := range Placeholders(p, h) {
		h[m.Path] = "file"
		if m.Dir {
			h[m.Path] = "dir"
		}
	}
	return h
}

func testProfile() *profile.Profile {
	return &profile.Profile{
		Name: "project",
		Mounts: []profile.Mount{
			{Path: "/home/u/Development/project/site", Mode: profile.ModeRead},
			{Path: "/home/u/Development/project", Mode: profile.ModeWrite},
			{Path: "/home/u/.nix-profile", Mode: profile.ModeRead, Optional: true},
			{Path: "/home/u/.missing", Mode: profile.ModeRead, Optional: true},
		},
		Caches:  []profile.Cache{{Path: "/home/u/.cache/go-build"}},
		Devices: []string{"/dev/tpmrm0"},
		Env:     profile.Env{Set: map[string]string{"LANG": "C.UTF-8"}, Pass: []string{"PATH", "TERM", "UNSET"}},
	}
}

func host() fakeHost {
	return fakeHost{
		"/home": "dir", "/run": "dir", "/tmp": "dir", "/var/tmp": "dir", "/mnt": "dir",
		"/home/u/Development/project":      "dir",
		"/home/u/Development/project/site": "dir",
		"/home/u/.nix-profile":              "other",
		"/dev/tpmrm0":                       "other",
	}
}

func layout() Layout {
	return Layout{JailDir: "/run/user/1000/g/s1/jail", CacheRoot: "/home/u/.cache/g/agents/project", Tmp: "/home/u/.cache/g/agents/project/tmp", Home: "/home/u/.cache/g/agents/project/scratch/s1", Exe: "/nix/store/x/bin/doriath"}
}

func opts() Options {
	return Options{
		UID:      1000,
		Home:     "/home/u",
		Cwd:      "/home/u/Development/project",
		Command:  []string{ExePath, "init", "--", "claude"},
		HostEnv:  map[string]string{"PATH": "/usr/bin", "TERM": "xterm", "GH_TOKEN": "secret", "SSH_AUTH_SOCK": "/run/user/1000/ssh-agent"},
		ExtraEnv: map[string]string{"HTTPS_PROXY": "http://127.0.0.1:3128"},
	}
}

func TestPlan(t *testing.T) {
	s, err := Plan(testProfile(), layout(), opts(), host())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.Tmpfs, []string{"/home", "/run", "/tmp", "/var/tmp", "/mnt"}) {
		t.Errorf("tmpfs = %v", s.Tmpfs)
	}
	var dests []string
	for _, b := range s.Binds {
		dests = append(dests, b.Dest)
	}
	want := []string{
		"/home/u",
		"/tmp",
		"/run/doriath",
		"/dev/tpmrm0",
		"/home/u/.nix-profile",
		"/run/doriath-bin/doriath",
		"/home/u/Development/project",
		"/home/u/Development/project/site",
		"/home/u/.cache/go-build",
	}
	slices.Sort(dests)
	slices.Sort(want)
	if !slices.Equal(dests, want) {
		t.Fatalf("binds = %v", dests)
	}
	idx := func(dest string) int {
		return slices.IndexFunc(s.Binds, func(b Bind) bool { return b.Dest == dest })
	}
	if idx("/home/u/Development/project") > idx("/home/u/Development/project/site") {
		t.Error("the parent mount must come before the read-only child")
	}
	cache := s.Binds[idx("/home/u/.cache/go-build")]
	if cache.Source != "/home/u/.cache/g/agents/project/home/.cache/go-build" || cache.ReadOnly {
		t.Errorf("cache bind = %+v", cache)
	}
	if b := s.Binds[idx("/run/doriath")]; !b.ReadOnly {
		t.Error("the doriath dir must be read-only in the jail")
	}
	if s.Env["GH_TOKEN"] != "" || s.Env["SSH_AUTH_SOCK"] != "" {
		t.Error("variables the profile does not pass must not reach the jail")
	}
	if s.Env["PATH"] != "/usr/bin" || s.Env["LANG"] != "C.UTF-8" || s.Env["HOME"] != "/home/u" || s.Env["XDG_RUNTIME_DIR"] != "/run/user/1000" || s.Env["HTTPS_PROXY"] == "" {
		t.Errorf("env = %v", s.Env)
	}
	if _, ok := s.Env["UNSET"]; ok {
		t.Error("a passed variable that is unset on the host must stay unset")
	}
}

func TestArgsOrder(t *testing.T) {
	s, err := Plan(testProfile(), layout(), opts(), host())
	if err != nil {
		t.Fatal(err)
	}
	args := s.Args()
	pos := func(want ...string) int {
		for i := range args {
			if slices.Equal(args[i:min(i+len(want), len(args))], want) {
				return i
			}
		}
		t.Fatalf("args missing %v: %v", want, args)
		return -1
	}
	root := pos("--ro-bind", "/", "/")
	if root > pos("--proc", "/proc") || root > pos("--tmpfs", "/home") {
		t.Error("the root bind must come before /proc and the tmpfs mounts")
	}
	if pos("--tmpfs", "/home") > pos("--bind", "/home/u/Development/project", "/home/u/Development/project") {
		t.Error("the home tmpfs must come before the binds into home")
	}
	if pos("--unshare-net") > root {
		t.Error("namespace flags come first")
	}
	clear := pos("--clearenv")
	if clear > pos("--setenv", "HOME", "/home/u") {
		t.Error("--clearenv must come before --setenv")
	}
	sep := pos("--")
	if !slices.Equal(args[sep+1:], []string{ExePath, "init", "--", "claude"}) {
		t.Errorf("command = %v", args[sep+1:])
	}
	pos("--dev-bind", "/dev/tpmrm0", "/dev/tpmrm0")
	pos("--chdir", "/home/u/Development/project")
}

func TestPlanErrors(t *testing.T) {
	p := testProfile()
	p.Mounts = append(p.Mounts, profile.Mount{Path: "/home/u/required", Mode: profile.ModeWrite})
	if _, err := Plan(p, layout(), opts(), host()); err == nil || !strings.Contains(err.Error(), "/home/u/required does not exist") {
		t.Errorf("err = %v", err)
	}
	o := opts()
	o.Cwd = "/home/u/elsewhere"
	if _, err := Plan(testProfile(), layout(), o, host()); err == nil || !strings.Contains(err.Error(), "not inside any mount") {
		t.Errorf("err = %v", err)
	}
	o = opts()
	o.Command = nil
	if _, err := Plan(testProfile(), layout(), o, host()); err == nil {
		t.Error("an empty command must be an error")
	}
	p = testProfile()
	p.Devices = []string{"/dev/nope"}
	if _, err := Plan(p, layout(), opts(), host()); err == nil {
		t.Error("a missing device must be an error")
	}
}

func TestCwdPrefixIsPathAware(t *testing.T) {
	o := opts()
	o.Cwd = "/home/u/Development/project-backup"
	if _, err := Plan(testProfile(), layout(), o, host()); err == nil {
		t.Fatal("a sibling directory sharing a prefix is not inside the mount")
	}
}

func TestGitGuards(t *testing.T) {
	h := host()
	h["/home/u/Development/project/.git"] = "dir"
	h["/home/u/Development/project/.git/config"] = "file"
	h["/home/u/Development/project/.git/hooks"] = "dir"
	s, err := Plan(testProfile(), layout(), opts(), held(testProfile(), h))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/home/u/Development/project/.git/config", "/home/u/Development/project/.git/hooks", "/home/u/Development/project/.git/info"} {
		if mode(s.Binds, p) != "read" {
			t.Errorf("%s must be bound read-only", p)
		}
	}
}

func TestMissingControlPathsAreHeld(t *testing.T) {
	repo := "/home/u/Development/project"
	h := host()
	h[repo+"/.git"] = "dir"
	h[repo+"/.git/config"] = "file"
	h[repo+"/.git/worktrees"] = "dir"
	h[repo+"/.git/worktrees/wt"] = "dir"
	h[repo+"/.jj"] = "dir"
	h[repo+"/.jj/repo"] = "dir"
	h[repo+"/.jj/repo/store/git_target"] = "file"
	if _, err := Plan(testProfile(), layout(), opts(), h); err == nil || !strings.Contains(err.Error(), repo+"/.git/hooks is missing") {
		t.Fatalf("a missing control path must stop the session: %v", err)
	}
	got := map[string]Placeholder{}
	for _, m := range Placeholders(testProfile(), h) {
		got[strings.TrimPrefix(m.Path, repo+"/")] = m
	}
	want := map[string]Placeholder{
		".git/hooks":                        {Dir: true},
		".git/info":                         {Dir: true},
		".git/config.worktree":              {},
		".git/objects/info/alternates":      {},
		".git/worktrees/wt/config.worktree": {},
		".jj/repo/config.toml":              {},
	}
	for rel, w := range want {
		if g, ok := got[rel]; !ok || g.Dir != w.Dir || g.Content != w.Content {
			t.Errorf("%s: %+v, want %+v", rel, g, w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("placeholders = %v", got)
	}
}

func TestSecondaryWorkspacePointerIsReadOnly(t *testing.T) {
	repo := "/home/u/Development/project"
	h := host()
	h[repo+"/.jj"] = "dir"
	h[repo+"/.jj/repo"] = "file"
	s, err := Plan(testProfile(), layout(), opts(), h)
	if err != nil {
		t.Fatal(err)
	}
	if mode(s.Binds, repo+"/.jj/repo") != "read" {
		t.Fatal("a workspace's .jj/repo pointer must be read-only, or the agent could point jj at a config it writes")
	}
}

func TestGitGuardsOnGitDirMount(t *testing.T) {
	h := host()
	h["/home/u/Development/project/.git"] = "dir"
	h["/home/u/Development/project/.git/hooks"] = "dir"
	p := testProfile()
	p.Mounts = []profile.Mount{
		{Path: "/home/u/Development/project", Mode: profile.ModeRead},
		{Path: "/home/u/Development/project/.git", Mode: profile.ModeWrite},
	}
	s, err := Plan(p, layout(), opts(), held(p, h))
	if err != nil {
		t.Fatal(err)
	}
	if mode(s.Binds, "/home/u/Development/project/.git/hooks") != "read" {
		t.Fatal("hooks must be read-only when .git itself is the mount")
	}
}

func TestNixDaemonHiddenUnlessGranted(t *testing.T) {
	h := host()
	h[nixDaemonDir] = "dir"
	s, err := Plan(testProfile(), layout(), opts(), h)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(s.Tmpfs, nixDaemonDir) {
		t.Fatal("the nix daemon socket must be hidden by default")
	}
	p := testProfile()
	p.NixDaemon = true
	s, err = Plan(p, layout(), opts(), h)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(s.Tmpfs, nixDaemonDir) {
		t.Fatal("a profile that grants the daemon must see it")
	}
}

func TestGitGuardsRedirectsAndSubmodules(t *testing.T) {
	h := host()
	repo := "/home/u/Development/project"
	for p, k := range map[string]string{
		repo + "/.git":                    "dir",
		repo + "/.git/config":             "file",
		repo + "/.git/commondir":          "file",
		repo + "/.git/config.worktree":    "file",
		repo + "/.git/modules":            "dir",
		repo + "/.git/modules/emu":        "dir",
		repo + "/.git/modules/emu/config": "file",
		repo + "/.git/modules/emu/hooks":  "dir",
	} {
		h[p] = k
	}
	s, err := Plan(testProfile(), layout(), opts(), held(testProfile(), h))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{".git/config.worktree", ".git/modules/emu/config", ".git/modules/emu/hooks"} {
		if mode(s.Binds, repo+"/"+p) != "read" {
			t.Errorf("%s must be read-only", p)
		}
	}
	if mode(s.Binds, repo+"/.git/commondir") != "none" {
		t.Error("a bind would keep a commondir that the root guard removes")
	}
	if roots := GitRoots(testProfile(), h); !slices.Contains(roots, repo+"/.git") || !slices.Contains(roots, repo+"/.git/modules/emu") {
		t.Errorf("the root guard must watch the store and its submodules: %q", roots)
	}
	w := host()
	w["/home/u/Development/project/.git"] = "file"
	s, err = Plan(testProfile(), layout(), opts(), w)
	if err != nil {
		t.Fatal(err)
	}
	if mode(s.Binds, repo+"/.git") != "read" {
		t.Error("a worktree's .git pointer file must be read-only")
	}
}

func TestNestedRepositoriesAreGuarded(t *testing.T) {
	h := host()
	nested := "/home/u/Development/project/vendor-not/inner"
	for p, k := range map[string]string{
		"/home/u/Development/project/vendor-not": "dir",
		nested:                                  "dir",
		nested + "/.git":                        "dir",
		nested + "/.git/config":                 "file",
		"/home/u/Development/project/.jj":      "dir",
		"/home/u/Development/project/.jj/repo": "dir",
		"/home/u/Development/project/.jj/repo/config.toml": "file",
	} {
		h[p] = k
	}
	s, err := Plan(testProfile(), layout(), opts(), held(testProfile(), h))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{nested + "/.git/config", "/home/u/Development/project/.jj/repo/config.toml"} {
		if mode(s.Binds, p) != "read" {
			t.Errorf("%s must be read-only", p)
		}
	}
}

func TestPathPrependComesFirst(t *testing.T) {
	p := testProfile()
	p.Env.Pass = append(p.Env.Pass, "PATH")
	p.Env.PathPrepend = []string{"/nix/store/a-xvfb/bin"}
	s, err := Plan(p, layout(), opts(), host())
	if err != nil {
		t.Fatal(err)
	}
	if s.Env["PATH"] != "/nix/store/a-xvfb/bin:/usr/bin" {
		t.Fatalf("PATH = %q", s.Env["PATH"])
	}
}

func TestVarAndOptAreHidden(t *testing.T) {
	h := host()
	h["/var"], h["/opt"] = "dir", "dir"
	s, err := Plan(testProfile(), layout(), opts(), h)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(s.Tmpfs, "/var") || !slices.Contains(s.Tmpfs, "/opt") {
		t.Fatalf("tmpfs = %v", s.Tmpfs)
	}
	if slices.Index(s.Tmpfs, "/var") > slices.Index(s.Tmpfs, "/var/tmp") {
		t.Error("/var must be emptied before /var/tmp, or it would hide it")
	}
	args := strings.Join(s.Args(), " ")
	if !strings.Contains(args, "--symlink ../run /var/run") {
		t.Errorf("/var/run must still lead to /run: %s", args)
	}
}

func TestHiddenPathsShowNothing(t *testing.T) {
	p := testProfile()
	p.Mounts = append(p.Mounts,
		profile.Mount{Path: "/home/u/Development/project/secrets", Mode: profile.ModeHide},
		profile.Mount{Path: "/home/u/Development/project/.env", Mode: profile.ModeHide},
		profile.Mount{Path: "/home/u/Development/project/gone", Mode: profile.ModeHide},
	)
	h := host()
	h["/home/u/Development/project/secrets"] = "dir"
	h["/home/u/Development/project/.env"] = "file"
	s, err := Plan(p, layout(), opts(), h)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"/home/u/Development/project/secrets": layout().EmptyDir(),
		"/home/u/Development/project/.env":    "/dev/null",
	}
	seen := map[string]int{}
	for i, b := range s.Binds {
		if source, ok := want[b.Dest]; ok {
			if b.Source != source || !b.ReadOnly {
				t.Errorf("hidden %s: %+v", b.Dest, b)
			}
			seen[b.Dest] = i
		}
		if b.Dest == "/home/u/Development/project/gone" {
			t.Error("a hidden path that does not exist needs no mount")
		}
	}
	for dest := range want {
		if _, ok := seen[dest]; !ok {
			t.Errorf("%s is not hidden", dest)
		}
	}
	for i, b := range s.Binds {
		if b.Dest == "/home/u/Development/project" && i > seen["/home/u/Development/project/secrets"] {
			t.Error("the hiding mount must come after the mount it hides in")
		}
	}
}

func TestLinksInWritableMountsAreRefused(t *testing.T) {
	repo := "/home/u/Development/project"
	for name, h := range map[string]fakeHost{
		"a mount under a linked directory": {repo + "/.claude": "link", repo + "/.claude/worktrees": "dir"},
		"a guard under a linked directory": {repo + "/.git": "dir", repo + "/.git/config": "file", repo + "/.git/hooks": "link"},
	} {
		t.Run(name, func(t *testing.T) {
			base := host()
			for k, v := range h {
				base[k] = v
			}
			p := testProfile()
			p.Mounts = append(p.Mounts, profile.Mount{Path: repo + "/.claude/worktrees", Mode: profile.ModeWrite, Optional: true})
			_, err := Plan(p, layout(), opts(), held(p, base))
			if err == nil || !strings.Contains(err.Error(), "goes through the symlink") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestLinksOutsideWritableMountsAreBound(t *testing.T) {
	h := host()
	h["/home/u/.nix-profile"] = "link"
	if _, err := Plan(testProfile(), layout(), opts(), h); err != nil {
		t.Fatalf("a link the agent could not have made must still mount: %v", err)
	}
}

func TestRepositoriesSkipLinkedDirectories(t *testing.T) {
	h := host()
	root := "/home/u/Development/project"
	h[root+"/other"] = "link"
	h[root+"/other/.git"] = "dir"
	if got := Repositories(root, h); slices.Contains(got, root+"/other") {
		t.Fatalf("repositories = %v", got)
	}
}

func TestHomeOutsideHiddenRootsIsHidden(t *testing.T) {
	p := testProfile()
	p.Mounts = []profile.Mount{{Path: "/data/home/u/work", Mode: profile.ModeWrite}}
	p.Caches = nil
	h := host()
	h["/data/home/u"] = "dir"
	h["/data/home/u/work"] = "dir"
	o := opts()
	o.Home, o.Cwd = "/data/home/u", "/data/home/u/work"
	s, err := Plan(p, layout(), o, h)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(s.Binds, Bind{Source: layout().Home, Dest: "/data/home/u"}) {
		t.Fatalf("binds = %v", s.Binds)
	}
}

func TestTheHomeIsOnDiskSoThatScratchFilesDoNotFillMemory(t *testing.T) {
	s, err := Plan(testProfile(), layout(), opts(), host())
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(s.Tmpfs, "/home/u") || !slices.Contains(s.Binds, Bind{Source: layout().Home, Dest: "/home/u"}) {
		t.Errorf("tmpfs = %v, binds = %v", s.Tmpfs, s.Binds)
	}
}

func TestTheScratchHomeDoesNotCountAsAMountForTheWorkingDirectory(t *testing.T) {
	o := opts()
	o.Cwd = "/home/u/elsewhere"
	if _, err := Plan(testProfile(), layout(), o, host()); err == nil || !strings.Contains(err.Error(), "not inside any mount") {
		t.Errorf("err = %v", err)
	}
}

func TestRepositoriesFindRepositoriesUpToTheirDepth(t *testing.T) {
	h := fakeHost{}
	add := func(p, kind string) {
		for d := filepath.Dir(p); d != "/"; d = filepath.Dir(d) {
			if h[d] == "" {
				h[d] = "dir"
			}
		}
		h[p] = kind
	}
	add("/m/.git", "dir")
	add("/m/worktree/.git", "file")
	add("/m/a/b/jj/.jj", "dir")
	add("/m/a/b/c/.git", "dir")
	add("/m/a/b/c/d/.git", "dir")
	add("/m/node_modules/dep/.git", "dir")
	got := Repositories("/m", h)
	slices.Sort(got)
	want := []string{"/m", "/m/a/b/c", "/m/a/b/jj", "/m/worktree"}
	if !slices.Equal(got, want) {
		t.Errorf("repositories = %v, want %v", got, want)
	}
}

func TestTheJJConfigIDOfAWritableRepositoryStaysReadOnly(t *testing.T) {
	repo := "/home/u/Development/project"
	h := held(testProfile(), host())
	h[repo+"/.jj"] = "dir"
	h[repo+"/.jj/repo"] = "dir"
	h[repo+"/.jj/repo/config-id"] = "file"
	h = held(testProfile(), h)
	s, err := Plan(testProfile(), layout(), opts(), h)
	if err != nil {
		t.Fatal(err)
	}
	if mode(s.Binds, repo+"/.jj/repo/config-id") != "read" {
		t.Error("config-id, which picks the jj config host jj trusts, is writable")
	}
}

func TestJJReposListsTheReposWhoseControlFilesTheJailGuards(t *testing.T) {
	h := host()
	writable := "/home/u/Development/project"
	readOnly := "/home/u/Development/project/site/vendor"
	workspace := "/home/u/Development/project/ws"
	for p, k := range map[string]string{
		writable + "/.jj":       "dir",
		writable + "/.jj/repo":  "dir",
		workspace + "/.jj":      "dir",
		workspace + "/.jj/repo": "file",
		readOnly + "/.jj":       "dir",
		readOnly + "/.jj/repo":  "dir",
	} {
		h[p] = k
	}
	p := testProfile()
	if got := JJRepos(p, h); !slices.Equal(got, []string{writable + "/.jj/repo"}) {
		t.Errorf("without the vcs store: %q", got)
	}
	p.VCSStore = true
	if got := JJRepos(p, h); !slices.Contains(got, writable+"/.jj/repo") || slices.Contains(got, workspace+"/.jj/repo") {
		t.Errorf("with the vcs store: %q", got)
	}
}
