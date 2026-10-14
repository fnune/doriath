package profile

import (
	iofs "io/fs"
	"net/http"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func loader(profiles, modules fstest.MapFS) *Loader {
	return &Loader{Profiles: profiles, Modules: []iofs.FS{modules}, Home: "/home/u"}
}

func file(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }

func TestLoadMergesModulesInOrder(t *testing.T) {
	modules := fstest.MapFS{
		"base.toml": file(`
[[mounts]]
path = "~/.nix-profile"
optional = true

[env]
pass = ["TERM"]
set = { LANG = "C.UTF-8" }

[egress]
allow = ["proxy.golang.org"]
`),
		"github.toml": file(`
modules = ["base"]

[[http]]
host = "api.github.com"
credential = { secret = "github", scheme = "bearer" }

[[http.rules]]
method = "POST"
path = "/repos/*/*/releases"
action = "approve"
summary = "Create a release"
`),
	}
	profiles := fstest.MapFS{
		"project.toml": file(`
modules = ["github", "base"]

[secrets.github]
command = ["rbw", "get", "github-project"]


[[mounts]]
path = "~/Development/project"
mode = "write"

[env]
set = { LANG = "en_US.UTF-8" }

[[http]]
host = "api.github.com"

[[http.rules]]
method = "PUT"
path = "/repos/*/*/pulls/*/merge"
action = "deny"
`),
	}
	p, err := loader(profiles, modules).Load("project")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Mounts; len(got) != 2 || got[0].Path != "/home/u/.nix-profile" || got[0].Mode != ModeRead || !got[0].Optional || got[1].Mode != ModeWrite {
		t.Errorf("mounts = %+v", got)
	}
	if p.Env.Set["LANG"] != "en_US.UTF-8" {
		t.Errorf("profile env must override module env, got %q", p.Env.Set["LANG"])
	}
	if got := p.Secrets["github"].Command; len(got) != 3 || got[2] != "github-project" {
		t.Errorf("secrets = %v", p.Secrets)
	}
	host, ok := p.Intercepted("api.github.com")
	if !ok || host.Credential == nil || host.Credential.Secret != "github" {
		t.Fatalf("intercepted host = %+v, %v", host, ok)
	}
	if len(host.Rules) != 2 || host.Rules[0].Method != http.MethodPut {
		t.Errorf("profile rules must come before module rules, got %+v", host.Rules)
	}
	if r, ok := host.Decide("POST", "/repos/fnune/project/releases", nil); !ok || r.Action != ActionApprove || r.Summary != "Create a release" {
		t.Errorf("Decide = %+v %v", r, ok)
	}
	if r, ok := host.Decide("GET", "/repos/fnune/project", nil); ok || r.Action != ActionApprove {
		t.Errorf("a credentialed host must hold unnamed requests, got %+v", r)
	}
	if p.Claude.ApprovalTimeout != defaultApprovalTimeout {
		t.Errorf("timeout = %v", p.Claude.ApprovalTimeout)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]struct {
		profile string
		modules fstest.MapFS
		want    string
	}{
		"unknown key":        {profile: `mountz = []`, want: "unknown keys: mountz"},
		"key in mixed case":  {profile: "[[http]]\nhost = \"a.com\"\n[[http.Rules]]\nmethod = \"GET\"\npath = \"/\"\naction = \"deny\"", want: "write it in lower case"},
		"bad mode":           {profile: "[[mounts]]\npath = \"/x\"\nmode = \"rwx\"", want: `mode "rwx"`},
		"relative path":      {profile: "[[mounts]]\npath = \"x\"", want: "must be absolute"},
		"bad host":           {profile: "[egress]\nallow = [\"https://x.com\"]", want: "host pattern"},
		"wildcard inside":    {profile: "[egress]\nallow = [\"a.*.com\"]", want: "host pattern"},
		"port range":         {profile: "[egress]\nports = [0]", want: "out of range"},
		"basic without user": {profile: "[[http]]\nhost = \"github.com\"\ncredential = { secret = \"gh\", scheme = \"basic\" }", want: "needs a username"},
		"bad action":         {profile: "[[http]]\nhost = \"github.com\"\ndefault = \"maybe\"", want: `action "maybe"`},
		"bad path glob":      {profile: "[[http]]\nhost = \"a.com\"\n[[http.rules]]\nmethod = \"GET\"\npath = \"/a*\"\naction = \"deny\"", want: "whole segment"},
		"cache outside home": {profile: "[[caches]]\npath = \"/var/cache\"", want: "inside the home"},
		"device outside dev": {profile: "devices = [\"/etc/passwd\"]", want: "under /dev"},
		"bad timeout":        {profile: "[claude]\napproval_timeout = \"soon\"", want: "approval_timeout"},
		"missing module":     {profile: `modules = ["nope"]`, want: `module "nope" not found`},
		"undefined secret":   {profile: "[[http]]\nhost = \"a.com\"\ncredential = { secret = \"gh\", scheme = \"bearer\" }", want: `add it under [secrets.gh]`},
		"undefined signing":  {profile: "[signing]\nkey = \"k\"", want: `add it under [secrets.k]`},
		"secret both":        {profile: "[secrets.x]\nfile = \"/a\"\ncommand = [\"b\"]", want: "exactly one of file, command or oauth"},
		"secret relative":    {profile: "[secrets.x]\nfile = \"rel\"", want: "must be absolute"},
		"writable nix store": {profile: "[[mounts]]\npath = \"/nix/store/x\"\nmode = \"write\"", want: "must not be writable"},
		"writable opt":       {profile: "[[mounts]]\npath = \"/opt/tool\"\nmode = \"write\"", want: "must not be writable"},
		"bad memory limit":   {profile: "[limits]\nmemory = \"8 GB\"", want: "limits memory"},
		"bad cpu limit":      {profile: "[limits]\ncpu = \"2\"", want: "limits cpu"},
		"negative tasks":     {profile: "[limits]\ntasks = -1", want: "limits tasks"},
		"bad image glob":     {profile: "[podman]\nimages = [\"docker.io/[\"]", want: "podman images"},
		"short image name":   {profile: "[podman]\nimages = [\"postgres\"]", want: "name the registry"},
		"module cycle": {
			profile: `modules = ["a"]`,
			modules: fstest.MapFS{"a.toml": file(`modules = ["b"]`), "b.toml": file(`modules = ["a"]`)},
			want:    "module cycle",
		},
		"match, which profiles no longer have": {
			profile: `match = ["~/x"]`,
			want:    "unknown key",
		},
		"module with secrets": {
			profile: `modules = ["a"]`,
			modules: fstest.MapFS{"a.toml": file("[secrets.gh]\nfile = \"/t\"")},
			want:    "belong in profiles",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			modules := tc.modules
			if modules == nil {
				modules = fstest.MapFS{}
			}
			_, err := loader(fstest.MapFS{"p.toml": file(tc.profile)}, modules).Load("p")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestHostPattern(t *testing.T) {
	p, _ := ParseHostPattern("*.githubusercontent.com")
	for host, want := range map[string]bool{
		"objects.githubusercontent.com":  true,
		"a.b.githubusercontent.com":      true,
		"githubusercontent.com":          false,
		"evilgithubusercontent.com":      false,
		"OBJECTS.githubusercontent.com.": true,
	} {
		if got := p.Match(host); got != want {
			t.Errorf("Match(%q) = %v", host, got)
		}
	}
}

func TestPathPattern(t *testing.T) {
	for pattern, cases := range map[string]map[string]bool{
		"/repos/*/*/releases": {
			"/repos/a/b/releases":     true,
			"/repos/a/b/releases?x=1": true,
			"/repos/a/b/releases/1":   false,
			"/repos/a/releases":       false,
		},
		"/repos/*/*/git/**": {
			"/repos/a/b/git":            true,
			"/repos/a/b/git/refs/heads": true,
			"/repos/a/b/gitx":           false,
		},
	} {
		p, err := ParsePathPattern(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for path, want := range cases {
			if got := p.Match(path); got != want {
				t.Errorf("%s Match(%q) = %v", pattern, path, got)
			}
		}
	}
}

func TestApprovalTimeout(t *testing.T) {
	p, err := loader(fstest.MapFS{"p.toml": file("[claude]\napproval_timeout = \"90s\"")}, fstest.MapFS{}).Load("p")
	if err != nil || p.Claude.ApprovalTimeout != 90*time.Second {
		t.Fatalf("got %v, %v", p, err)
	}
}

func TestPathPrepend(t *testing.T) {
	modules := fstest.MapFS{"tools.toml": file("[env]\npath_prepend = [\"/nix/store/a-xvfb/bin\"]")}
	p, err := loader(fstest.MapFS{"p.toml": file("modules = [\"tools\"]\n[env]\npath_prepend = [\"~/bin\", \"/nix/store/a-xvfb/bin\"]")}, modules).Load("p")
	if err != nil || !slices.Equal(p.Env.PathPrepend, []string{"/nix/store/a-xvfb/bin", "/home/u/bin"}) {
		t.Fatalf("path_prepend = %v, %v", p.Env.PathPrepend, err)
	}
	if _, err := loader(fstest.MapFS{"p.toml": file("[env]\npath_prepend = [\"/a:/b\"]")}, fstest.MapFS{}).Load("p"); err == nil {
		t.Fatal("a colon would split into two PATH entries")
	}
}

func TestLimits(t *testing.T) {
	empty := fstest.MapFS{}
	p, err := loader(fstest.MapFS{"p.toml": file("")}, empty).Load("p")
	if err != nil || p.Limits != (Limits{Tasks: DefaultTaskLimit, Memory: DefaultMemoryLimit}) {
		t.Fatalf("default limits = %+v, %v", p.Limits, err)
	}
	p, err = loader(fstest.MapFS{"p.toml": file("[limits]\ntasks = 0\nmemory = \"8G\"\ncpu = \"200%\"")}, empty).Load("p")
	if err != nil || p.Limits != (Limits{Memory: "8G", CPU: "200%"}) {
		t.Fatalf("limits = %+v, %v", p.Limits, err)
	}
}

func TestBodyRules(t *testing.T) {
	profiles := fstest.MapFS{"p.toml": file(`
[[http]]
host = "api.github.com"

[[http.rules]]
method = "POST"
path = "/graphql"
body_contains = ["mergePullRequest", "enablePullRequestAutoMerge"]
action = "approve"
summary = "Merge a pull request"
`)}
	p, err := loader(profiles, fstest.MapFS{}).Load("p")
	if err != nil {
		t.Fatal(err)
	}
	h, _ := p.Intercepted("api.github.com")
	if !h.NeedsBody("POST", "/graphql") || h.NeedsBody("GET", "/graphql") || h.NeedsBody("POST", "/user") {
		t.Error("NeedsBody")
	}
	if r, ok := h.Decide("POST", "/graphql", []byte(`{"query":"mutation { mergePullRequest(input:{}) { x } }"}`)); !ok || r.Action != ActionApprove {
		t.Errorf("merge mutation: %+v %v", r, ok)
	}
	if _, ok := h.Decide("POST", "/graphql", []byte(`{"query":"query { viewer { login } }"}`)); ok {
		t.Error("a read query must not match")
	}
	if _, err := loader(fstest.MapFS{"p.toml": file("[[http]]\nhost = \"a.com\"\n[[http.rules]]\npath = \"/\"\naction = \"deny\"\nbody_contains = [\"\"]")}, fstest.MapFS{}).Load("p"); err == nil {
		t.Error("empty body_contains entry must be rejected")
	}
}

func TestCredentialBinaries(t *testing.T) {
	c := Credential{Binaries: []string{"gh", "git-remote-https", "/home/u/bin/tool"}}
	for exe, want := range map[string]bool{
		"/nix/store/abc-gh-2.76/bin/gh":                      true,
		"/nix/store/abc-gh-2.76/bin/.gh-wrapped":             true,
		"/usr/lib/git-core/git-remote-https":                 true,
		"/nix/store/x-git/libexec/git-core/git-remote-https": true,
		"/home/u/bin/tool":                                   true,
		"/home/u/Development/k/gh":                           false,
		"/tmp/gh":                                            false,
		"/nix/store/abc-curl/bin/curl":                       false,
		"":                                                   false,
	} {
		if got := c.AllowsBinary(exe); got != want {
			t.Errorf("AllowsBinary(%q) = %v, want %v", exe, got, want)
		}
	}
	if !(Credential{}).AllowsBinary("") {
		t.Error("no list means any program")
	}
}

func TestProgramEgress(t *testing.T) {
	body := `
[egress]
allow = ["registry.npmjs.org"]

[[egress.programs]]
binaries = ["chrome", "~/.cache/ms-playwright/*/chrome-linux64/chrome"]
allow = ["*.launchdarkly.com"]
`
	p, err := loader(fstest.MapFS{"p.toml": file(body)}, fstest.MapFS{}).Load("p")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		host, exe string
		want      bool
	}{
		{"registry.npmjs.org", "/usr/bin/curl", true},
		{"events.launchdarkly.com", "/nix/store/x-chromium/bin/chrome", true},
		{"events.launchdarkly.com", "/home/u/.cache/ms-playwright/chromium-1243/chrome-linux64/chrome", true},
		{"events.launchdarkly.com", "/usr/bin/curl", false},
		{"events.launchdarkly.com", "/home/u/bin/chrome", false},
		{"events.launchdarkly.com", "", false},
	} {
		if got := p.AllowsHostFor(c.host, c.exe); got != c.want {
			t.Errorf("AllowsHostFor(%s, %s) = %v, want %v", c.host, c.exe, got, c.want)
		}
	}
	if p.AllowsHost("events.launchdarkly.com") {
		t.Error("a program-only host must not be open to every program")
	}
	if got := p.ProgramsFor("events.launchdarkly.com"); len(got) != 2 {
		t.Errorf("ProgramsFor = %v", got)
	}
	for _, bad := range []string{
		"[[egress.programs]]\nallow = [\"a.com\"]",
		"[[egress.programs]]\nbinaries = [\"rel/chrome\"]\nallow = [\"a.com\"]",
		"[[egress.programs]]\nbinaries = [\"chrome\"]\nallow = [\"https://a.com\"]",
	} {
		if _, err := loader(fstest.MapFS{"p.toml": file(bad)}, fstest.MapFS{}).Load("p"); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
