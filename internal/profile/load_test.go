package profile

import (
	iofs "io/fs"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
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
missing = "skip"

[env]
pass = ["TERM"]
set = { LANG = "C.UTF-8" }

[egress]
allow = ["proxy.golang.org"]
`),
		"github.toml": file(`
modules = ["base"]
uses_secrets = ["github"]

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
	if got := p.Mounts; len(got) != 2 || got[0].Path != "/home/u/.nix-profile" || got[0].Mode != ModeRead || got[0].Missing != MissingSkip || got[1].Mode != ModeWrite {
		t.Errorf("mounts = %+v", got)
	}
	if p.Env.Set["LANG"] != "en_US.UTF-8" {
		t.Errorf("profile env must override module env, got %q", p.Env.Set["LANG"])
	}
	if got := p.Secrets["github"].Command; len(got) != 3 || got[2] != "github-project" {
		t.Errorf("secrets = %v", p.Secrets)
	}
	if src := p.Sources["secret github for github"]; !slices.Equal(src, []string{"github"}) {
		t.Errorf("a module's secret must be shown with the module, got sources %v", p.Sources)
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
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]struct {
		profile string
		modules fstest.MapFS
		want    string
	}{
		"unknown key":             {profile: `mountz = []`, want: "unknown keys: mountz"},
		"key in mixed case":       {profile: "[[http]]\nhost = \"a.com\"\n[[http.Rules]]\nmethod = \"GET\"\npath = \"/\"\naction = \"deny\"", want: "write it in lower case"},
		"bad mode":                {profile: "[[mounts]]\npath = \"/x\"\nmode = \"rwx\"", want: `mode "rwx"`},
		"relative path":           {profile: "[[mounts]]\npath = \"x\"", want: "must be absolute"},
		"bad host":                {profile: "[egress]\nallow = [\"https://x.com\"]", want: "host pattern"},
		"wildcard inside":         {profile: "[egress]\nallow = [\"a.*.com\"]", want: "host pattern"},
		"port range":              {profile: "[egress]\nports = [0]", want: "out of range"},
		"basic without user":      {profile: "[[http]]\nhost = \"github.com\"\ncredential = { secret = \"gh\", scheme = \"basic\" }", want: "needs a username"},
		"bad action":              {profile: "[[http]]\nhost = \"github.com\"\ndefault = \"maybe\"", want: `action "maybe"`},
		"bad path glob":           {profile: "[[http]]\nhost = \"a.com\"\n[[http.rules]]\nmethod = \"GET\"\npath = \"/a*\"\naction = \"deny\"", want: "whole segment"},
		"cache outside home":      {profile: "[[caches]]\npath = \"/var/cache\"", want: "inside the home"},
		"device outside dev":      {profile: "devices = [\"/etc/passwd\"]", want: "under /dev"},
		"missing module":          {profile: `modules = ["nope"]`, want: `module "nope" not found`},
		"undefined secret":        {profile: "[[http]]\nhost = \"a.com\"\ncredential = { secret = \"gh\", scheme = \"bearer\" }", want: `add it under [secrets.gh]`},
		"undefined signing":       {profile: "[signing]\nkey = \"k\"", want: `add it under [secrets.k]`},
		"secret both":             {profile: "[secrets.x]\nfile = \"/a\"\ncommand = [\"b\"]", want: "exactly one of file, command, keyring or oauth"},
		"secret keyring and file": {profile: "[secrets.x]\nfile = \"/a\"\nkeyring = true", want: "exactly one of file, command, keyring or oauth"},
		"secret relative":         {profile: "[secrets.x]\nfile = \"rel\"", want: "must be absolute"},
		"writable nix store":      {profile: "[[mounts]]\npath = \"/nix/store/x\"\nmode = \"write\"", want: "must not be writable"},
		"writable opt":            {profile: "[[mounts]]\npath = \"/opt/tool\"\nmode = \"write\"", want: "must not be writable"},
		"bad memory limit":        {profile: "[limits]\nmemory = \"8 GB\"", want: "limits memory"},
		"bad cpu limit":           {profile: "[limits]\ncpu = \"2\"", want: "limits cpu"},
		"negative tasks":          {profile: "[limits]\ntasks = -1", want: "limits tasks"},
		"bad image glob":          {profile: "[podman]\nimages = [\"docker.io/[\"]", want: "podman images"},
		"short image name":        {profile: "[podman]\nimages = [\"postgres\"]", want: "name the registry"},
		"name field differs":      {profile: `name = "q"`, want: `name field says "q"`},
		"bad env name":            {profile: "[env]\nset = { \"1X\" = \"a\" }", want: `env set "1X": invalid variable name`},
		"bad env pass":            {profile: "[env]\npass = [\"A-B\"]", want: `env pass "A-B": invalid variable name`},
		"port twice":              {profile: "[egress]\nports = [5432]\ntcp_ports = [5432]", want: "listed both as HTTP and as TCP"},
		"bad host label":          {profile: "[egress]\nallow = [\"a_b.com\"]", want: `invalid label "a_b"`},
		"bad secret name":         {profile: "[secrets.\"g h\"]\nfile = \"/a\"", want: "use lowercase letters"},
		"bad credential secret": {
			profile: "[[http]]\nhost = \"a.com\"\ncredential = { secret = \"G\" }",
			want:    `secret "G": use lowercase letters`,
		},
		"username without basic": {
			profile: "[secrets.gh]\nfile = \"/a\"\n[[http]]\nhost = \"a.com\"\ncredential = { secret = \"gh\", username = \"x\" }",
			want:    "username is only used with the basic scheme",
		},
		"unknown scheme": {
			profile: "[secrets.gh]\nfile = \"/a\"\n[[http]]\nhost = \"a.com\"\ncredential = { secret = \"gh\", scheme = \"digest\" }",
			want:    "want bearer, token, basic, header or sigv4",
		},
		"empty credential binary": {
			profile: "[secrets.gh]\nfile = \"/a\"\n[[http]]\nhost = \"a.com\"\ncredential = { secret = \"gh\", binaries = [\"\"] }",
			want:    "binaries entries must not be empty",
		},
		"relative credential binary": {
			profile: "[secrets.gh]\nfile = \"/a\"\n[[http]]\nhost = \"a.com\"\ncredential = { secret = \"gh\", binaries = [\"bin/gh\"] }",
			want:    `binary "bin/gh": a path must be absolute`,
		},
		"lower-case method":    {profile: "[[http]]\nhost = \"a.com\"\n[[http.rules]]\nmethod = \"get\"\npath = \"/\"\naction = \"deny\"", want: "want an uppercase HTTP method"},
		"relative rule path":   {profile: "[[http]]\nhost = \"a.com\"\n[[http.rules]]\nmethod = \"GET\"\npath = \"a\"\naction = \"deny\"", want: "must start with /"},
		"double star twice":    {profile: "[[http]]\nhost = \"a.com\"\n[[http.rules]]\nmethod = \"GET\"\npath = \"/**/**/a\"\naction = \"deny\"", want: "** twice in a row"},
		"bad header name":      {profile: "[[http]]\nhost = \"a.com\"\n[[http.rules]]\nmethod = \"GET\"\npath = \"/\"\nheader = \"x api\"\naction = \"deny\"", want: "want a header name"},
		"header prefix alone":  {profile: "[[http]]\nhost = \"a.com\"\n[[http.rules]]\nmethod = \"GET\"\npath = \"/\"\nheader_prefix = \"Bearer \"\naction = \"deny\"", want: "header_prefix needs header"},
		"empty program binary": {profile: "[[egress.programs]]\nbinaries = [\"\"]\nallow = [\"a.com\"]", want: "binaries entries must not be empty"},
		"env on a remote mcp":  {profile: "[[mcp]]\nname = \"n\"\nurl = \"https://a.com/mcp\"\nenv = { A = \"1\" }", want: "env is for local servers"},
		"bad mcp secret":       {profile: "[[mcp]]\nname = \"n\"\nurl = \"https://a.com/mcp\"\nsecret = \"N\"", want: `secret "N": use lowercase letters`},
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
		"bad missing": {profile: "[[mounts]]\npath = \"/x\"\nmissing = \"maybe\"", want: `missing "maybe": want error, skip or hold`},
		"module credential with an undeclared secret": {
			profile: "modules = [\"a\"]\n[secrets.gh]\nfile = \"/t\"",
			modules: fstest.MapFS{"a.toml": file("[[http]]\nhost = \"evil.example\"\ncredential = { secret = \"gh\", scheme = \"bearer\" }")},
			want:    `module "a": it hands secret "gh"`,
		},
		"module rule credential with an undeclared secret": {
			profile: "modules = [\"a\"]\n[secrets.gh]\nfile = \"/t\"",
			modules: fstest.MapFS{"a.toml": file("[[http]]\nhost = \"a.com\"\n[[http.rules]]\nmethod = \"GET\"\npath = \"/\"\naction = \"allow\"\ncredential = { secret = \"gh\", scheme = \"bearer\" }")},
			want:    `module "a": it hands secret "gh"`,
		},
		"module signing with an undeclared key": {
			profile: "modules = [\"a\"]\n[secrets.k]\nfile = \"/t\"",
			modules: fstest.MapFS{"a.toml": file("[signing]\nkey = \"k\"")},
			want:    `module "a": it hands secret "k"`,
		},
		"module mcp server with an undeclared secret": {
			profile: "modules = [\"a\"]\n[secrets.n]\nfile = \"/t\"",
			modules: fstest.MapFS{"a.toml": file("[[mcp]]\nname = \"n\"\nurl = \"https://a.com/mcp\"\nsecret = \"n\"")},
			want:    `module "a": it hands secret "n"`,
		},
		"uses_secrets in a profile": {
			profile: `uses_secrets = ["gh"]`,
			want:    "uses_secrets is for modules",
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

func TestLoadRejectsBadNames(t *testing.T) {
	l := loader(fstest.MapFS{"p.toml": file(`modules = ["Base"]`)}, fstest.MapFS{})
	if _, err := l.Load("P"); err == nil || err.Error() != `profile name "P": use lowercase letters, digits and dashes` {
		t.Errorf("profile: err = %v", err)
	}
	if _, err := l.Load("p"); err == nil || !strings.Contains(err.Error(), `module name "Base": use lowercase letters, digits and dashes`) {
		t.Errorf("module: err = %v", err)
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
		"/**/git-receive-pack": {
			"/o/r.git/git-receive-pack":            true,
			"/group/sub/proj.git/git-receive-pack": true,
			"/git-receive-pack":                    true,
			"/o/r.git/git-upload-pack":             false,
			"/o/r.git/git-receive-pack/x":          false,
		},
		"/api/**/merge": {
			"/api/merge": true,
			"/api/v4/projects/1/merge_requests/2/merge": true,
			"/api/v4/merge/x": false,
			"/other/merge":    false,
		},
		"/": {
			"/":  true,
			"/a": false,
		},
		"/**": {
			"/":    true,
			"/a/b": true,
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

func TestSSHRemoteDefaultsAndLimits(t *testing.T) {
	load := func(body string) (*Profile, error) {
		return loader(fstest.MapFS{"p.toml": file(body)}, fstest.MapFS{}).Load("p")
	}
	p, err := load("[[http]]\nhost = \"codeberg.org\"\nssh = {}\n")
	if err != nil || p.HTTP[0].SSH == nil || !reflect.DeepEqual(*p.HTTP[0].SSH, SSHRemote{User: "git", Port: 22}) {
		t.Fatalf("defaults: %+v, %v", p, err)
	}
	for _, body := range []string{
		"[[http]]\nhost = \"*.example.org\"\nssh = {}\n",
		"[[http]]\nhost = \"bitbucket.org\"\nssh = { hosts = [\"*.bitbucket.org\"] }\n",
		"[[http]]\nhost = \"bitbucket.org\"\nssh = { hosts = [\"ssh.bitbucket.org:22\"] }\n",
		"[[http]]\nhost = \"example.org\"\nssh = { port = 70000 }\n",
		"[[http]]\nhost = \"example.org\"\nssh = { user = \"git; rm\" }\n",
	} {
		if _, err := load(body); err == nil {
			t.Errorf("%q must be refused", body)
		}
	}
	if p, err := load("[[http]]\nhost = \"example.org\"\ncredential = { secret = \"s\", scheme = \"basic\", username = \"u\" }\n[secrets.s]\ncommand = [\"true\"]\n"); err != nil || p.HTTP[0].SSH != nil {
		t.Fatalf("a basic credential alone must not turn on the rewrite: %+v, %v", p, err)
	}
}

func TestRuleCredentialsNeedTheirSecret(t *testing.T) {
	_, err := loader(fstest.MapFS{"p.toml": file("[[http]]\nhost = \"gitlab.com\"\n[[http.rules]]\npath = \"/api/**\"\naction = \"allow\"\ncredential = { secret = \"gitlab\", scheme = \"header\", header = \"PRIVATE-TOKEN\" }\n")}, fstest.MapFS{}).Load("p")
	if err == nil || !strings.Contains(err.Error(), "[secrets.gitlab]") {
		t.Fatalf("got %v", err)
	}
	_, err = loader(fstest.MapFS{"p.toml": file("[secrets.gitlab]\ncommand = [\"true\"]\n[[http]]\nhost = \"gitlab.com\"\ncredential = { secret = \"gitlab\", scheme = \"header\" }\n")}, fstest.MapFS{}).Load("p")
	if err == nil || !strings.Contains(err.Error(), "needs a header name") {
		t.Fatalf("a header scheme without a header: %v", err)
	}
}

func TestHostPatternsWithAPort(t *testing.T) {
	p, err := ParseHostPattern("Git.Example.org:3000")
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]bool{
		"git.example.org:3000": true,
		"git.example.org":      false,
		"git.example.org:3001": false,
	} {
		if got := p.Match(target); got != want {
			t.Errorf("%s.Match(%q) = %v", p, target, got)
		}
	}
	plain, _ := ParseHostPattern("example.org")
	if plain.Match("example.org:8443") || !plain.Match("example.org") {
		t.Error("a pattern without a port must match only the default port")
	}
	for _, bad := range []string{"example.org:", "example.org:0", "example.org:70000", "example.org:08", "example.org:x", "*:80"} {
		if _, err := ParseHostPattern(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	if Target("Example.org", "443", "443") != "example.org" || Target("example.org", "8443", "443") != "example.org:8443" || Target("2001:db8::1", "8443", "443") != "[2001:db8::1]:8443" {
		t.Error("Target")
	}
	if h, port := SplitTarget("[2001:db8::1]:8443"); h != "2001:db8::1" || port != "8443" {
		t.Errorf("SplitTarget = %q, %q", h, port)
	}
	if h, port := SplitTarget("2001:db8::1"); h != "2001:db8::1" || port != "" {
		t.Errorf("SplitTarget of a bare IPv6 address = %q, %q", h, port)
	}
}

func TestCredentialBinariesStartWithTheHomeAsEgressProgramsDo(t *testing.T) {
	l := &Loader{Profiles: fstest.MapFS{"p.toml": {Data: []byte(`
[secrets.t]
command = ["true"]

[[http]]
host = "api.example.com"
credential = { secret = "t", scheme = "bearer", binaries = ["~/.cache/tool/bin/tool", "gh"] }
`)}}, Home: "/home/u"}
	p, err := l.Load("p")
	if err != nil {
		t.Fatal(err)
	}
	h, _ := p.Intercepted("api.example.com")
	if got := h.Credential.Binaries; !slices.Equal(got, []string{"/home/u/.cache/tool/bin/tool", "gh"}) {
		t.Errorf("binaries = %v", got)
	}
	l.Profiles = fstest.MapFS{"p.toml": {Data: []byte(`
[secrets.t]
command = ["true"]

[[http]]
host = "api.example.com"
credential = { secret = "t", scheme = "bearer", binaries = ["bin/tool"] }
`)}}
	if _, err := l.Load("p"); err == nil {
		t.Error("a relative path must be refused")
	}
}

func TestASecretIsOptionalUnlessItSaysRequiredOrSigns(t *testing.T) {
	body := `[secrets.github]
command = ["gh-token"]

[secrets.deploy]
command = ["deploy-token"]
required = true

[secrets.signing]
file = "~/.config/doriath/keys/agent-signing"

[signing]
key = "signing"
`
	p, err := loader(fstest.MapFS{"app.toml": file(body)}, fstest.MapFS{}).Load("app")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"github": false, "deploy": true, "signing": true} {
		if got := p.Secrets[name].Required; got != want {
			t.Errorf("secret %s: required = %v, want %v", name, got, want)
		}
	}
}

func TestAModuleNotesWhatAHostIsAndTheNoteGrantsNothing(t *testing.T) {
	modules := fstest.MapFS{"agent.toml": file("[egress]\nnotes = { \"proxy.example\" = \"The agent's connector proxy.\" }\n")}
	p, err := loader(fstest.MapFS{"app.toml": file(`modules = ["agent"]`)}, modules).Load("app")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.HostNote("proxy.example"); got != "The agent's connector proxy." {
		t.Errorf("note = %q", got)
	}
	if p.AllowsHost("proxy.example") {
		t.Error("a note allowed the host")
	}
	grants, err := p.Grants()
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range grants {
		if strings.Contains(g, "Notes") {
			t.Errorf("a note is a grant: %s", g)
		}
	}
}

func TestAProfileOpenRuleComesBeforeItsModules(t *testing.T) {
	modules := fstest.MapFS{"agent.toml": file("[[open]]\nhost = \"login.example\"\npath = \"/oauth/authorize\"\naction = \"allow\"\nforward_redirect = true\n")}
	profiles := fstest.MapFS{"app.toml": file("modules = [\"agent\"]\n\n[[open]]\nhost = \"login.example\"\naction = \"deny\"\n")}
	p, err := loader(profiles, modules).Load("app")
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := p.OpenRule("login.example", "/oauth/authorize"); !ok || r.Action != ActionDeny {
		t.Errorf("rule = %+v, %v", r, ok)
	}
	modulesOnly, err := loader(fstest.MapFS{"app.toml": file(`modules = ["agent"]`)}, modules).Load("app")
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := modulesOnly.OpenRule("login.example", "/oauth/authorize"); !ok || r.Action != ActionAllow || !r.ForwardRedirect {
		t.Errorf("module rule = %+v, %v", r, ok)
	}
	if _, ok := modulesOnly.OpenRule("login.example", "/elsewhere"); ok {
		t.Error("a rule matched a path it does not name")
	}
}

func TestSourcesNameWhatDecidesWhereSecretsGo(t *testing.T) {
	p, err := loader(fstest.MapFS{"app.toml": file(`
[secrets.gh]
command = ["pass", "show", "gh"]

[secrets.key]
file = "~/.config/doriath/keys/key"

[secrets.forge]
keyring = true

[[http]]
host = "api.example"
credential = { secret = "gh", binaries = ["gh", "curl"] }
default = "allow"

[[http.rules]]
method = "POST"
path = "/upload"
action = "allow"
credential = { secret = "key" }

[[open]]
host = "www.example"
path = "/**"
action = "allow"

[[mounts]]
path = "{git}/config"
edit = { format = "git-config", safe = ["core.hookspath = **"] }

[nix]
daemon = true

[hardening]
landlock = false

[signing]
enable = false

[limits]
cpu = "200%"
`)}, fstest.MapFS{}).Load("app")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"source gh: command pass show gh",
		"source key: file ~/.config/doriath/keys/key",
		"source forge: keyring",
		"credential api.example: gh for gh, curl",
		"credential api.example POST /upload: key for any program",
		"default api.example: allow",
		"open www.example /**: allow",
		"setting edit {git}/config: safe without asking: core.hookspath = **",
		"setting nix.daemon = true",
		"setting hardening.landlock = false",
		"setting signing.enable = false",
		"setting limits.cpu = 200%",
	} {
		if p.Sources[key] == nil {
			t.Errorf("no source %q; have %v", key, slices.Sorted(maps.Keys(p.Sources)))
		}
	}
}

func TestAllowedMCPServersReachTheProfile(t *testing.T) {
	p, err := loader(fstest.MapFS{
		"app.toml": file("modules = [\"docs\"]\n\n[claude]\nallowed_mcp_servers = [\"https://mcp.example.com/mcp\"]\n"),
	}, fstest.MapFS{
		"docs.toml": file("[claude]\nallowed_mcp_servers = [\"bazel\"]\n"),
	}).Load("app")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Claude.AllowedMCPServers, []string{"bazel", "https://mcp.example.com/mcp"}) {
		t.Errorf("allowed MCP servers = %q", p.Claude.AllowedMCPServers)
	}
}

func TestCodeArchivesMergeAcrossModulesAndExpandTheHome(t *testing.T) {
	modules := fstest.MapFS{
		"a.toml": file("[code]\narchives = [\"~/.cache/bazel/_bazel_*/install/*/A-server.jar\"]\nlibraries = [\"~/lib/a.so\"]\n"),
		"b.toml": file("[code]\narchives = [\"/opt/tool/lib.jar\", \"~/.cache/bazel/_bazel_*/install/*/A-server.jar\"]\n"),
	}
	p, err := loader(fstest.MapFS{"p.toml": file("modules = [\"a\", \"b\"]\n")}, modules).Load("p")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/home/u/.cache/bazel/_bazel_*/install/*/A-server.jar", "/opt/tool/lib.jar"}
	if !slices.Equal(p.CodeArchives, want) {
		t.Errorf("archives = %v, want %v", p.CodeArchives, want)
	}
	if !slices.Equal(p.CodeLibraries, []string{"/home/u/lib/a.so"}) {
		t.Errorf("libraries = %v", p.CodeLibraries)
	}
	if _, err := loader(fstest.MapFS{"p.toml": file("[code]\narchives = [\"relative/a.jar\"]\n")}, nil).Load("p"); err == nil || !strings.Contains(err.Error(), "code archive") {
		t.Errorf("a relative archive path must fail: %v", err)
	}
}
