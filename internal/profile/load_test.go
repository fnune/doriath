package profile

import (
	iofs "io/fs"
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
match = ["~/Development/project"]
secrets = { github = "github-project" }

[[mounts]]
path = "~/Development/project"
mode = "rw"

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
	if got := p.Mounts; len(got) != 2 || got[0].Path != "/home/u/.nix-profile" || got[0].Mode != ModeReadOnly || !got[0].Optional || got[1].Mode != ModeReadWrite {
		t.Errorf("mounts = %+v", got)
	}
	if p.Env.Set["LANG"] != "en_US.UTF-8" {
		t.Errorf("profile env must override module env, got %q", p.Env.Set["LANG"])
	}
	if p.SecretName("github") != "github-project" || p.SecretName("other") != "other" {
		t.Errorf("secret aliases not applied: %v", p.Secrets)
	}
	host, ok := p.Intercepted("api.github.com")
	if !ok || host.Credential == nil || host.Credential.Secret != "github" {
		t.Fatalf("intercepted host = %+v, %v", host, ok)
	}
	if len(host.Rules) != 2 || host.Rules[0].Method != "PUT" {
		t.Errorf("profile rules must come before module rules, got %+v", host.Rules)
	}
	if a, s := host.Decide("POST", "/repos/fnune/project/releases"); a != ActionApprove || s != "Create a release" {
		t.Errorf("Decide = %v %q", a, s)
	}
	if a, _ := host.Decide("GET", "/repos/fnune/project"); a != ActionAllow {
		t.Errorf("default action = %v", a)
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
		"module cycle": {
			profile: `modules = ["a"]`,
			modules: fstest.MapFS{"a.toml": file(`modules = ["b"]`), "b.toml": file(`modules = ["a"]`)},
			want:    "module cycle",
		},
		"module with match": {
			profile: `modules = ["a"]`,
			modules: fstest.MapFS{"a.toml": file(`match = ["/x"]`)},
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

func TestFindPrefersLongestMatch(t *testing.T) {
	profiles := fstest.MapFS{
		"dev.toml":      file(`match = ["~/Development"]`),
		"project.toml": file(`match = ["~/Development/project"]`),
	}
	l := loader(profiles, fstest.MapFS{})
	p, err := l.Find("/home/u/Development/project/site")
	if err != nil || p.Name != "project" {
		t.Fatalf("Find = %v, %v", p, err)
	}
	p, err = l.Find("/home/u/Development/other")
	if err != nil || p.Name != "dev" {
		t.Fatalf("Find = %v, %v", p, err)
	}
	if _, err := l.Find("/home/u/Development-other"); err == nil {
		t.Fatal("a sibling directory with a shared prefix must not match")
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
