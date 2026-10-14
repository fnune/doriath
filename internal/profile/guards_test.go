package profile

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

func load(t *testing.T, profile string, modules fstest.MapFS) (*Profile, error) {
	t.Helper()
	if modules == nil {
		modules = fstest.MapFS{}
	}
	return loader(fstest.MapFS{"p.toml": file(profile)}, modules).Load("p")
}

func mustLoad(t *testing.T, profile string, modules fstest.MapFS) *Profile {
	t.Helper()
	p, err := load(t, profile, modules)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadRejectsUnsafeSettings(t *testing.T) {
	cases := map[string]struct{ profile, want string }{
		"cache is the home":     {"[[caches]]\npath = \"~\"", "inside the home"},
		"old mode name":         {"[[mounts]]\npath = \"/x\"\nmode = \"rw\"", "want read, write or hide"},
		"live, which is gone":   {"[[mounts]]\npath = \"/x\"\nlive = true", "unknown key"},
		"port above range":      {"[egress]\nports = [65536]", "out of range"},
		"tcp port above range":  {"[egress]\ntcp_ports = [65536]", "out of range"},
		"zero approval timeout": {"[claude]\napproval_timeout = \"0s\"", "approval_timeout"},
		"mount of the root":     {"[[mounts]]\npath = \"/\"", "whole filesystem"},
		"mount of the home":     {"[[mounts]]\npath = \"~\"", "whole home"},
		"mount above the home":  {"[[mounts]]\npath = \"/home\"", "whole home"},
		"writable home mount":   {"[[mounts]]\npath = \"~/\"\nmode = \"write\"", "whole home"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := load(t, tc.profile, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestLoadAcceptsEdgeSettings(t *testing.T) {
	for name, profile := range map[string]string{
		"name field matches file": "name = \"p\"",
		"hidden path":             "[[mounts]]\npath = \"/x/secret\"\nmode = \"hide\"",
		"writable mount":          "[[mounts]]\npath = \"/x\"\nmode = \"write\"",
		"lowest and highest port": "[egress]\nports = [1, 65535]\ntcp_ports = [2, 65534]",
		"nix without daemon":      "[nix]",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := load(t, profile, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLocalLayerCannotWidenTheProfile(t *testing.T) {
	for name, local := range map[string]string{
		"modules": "modules = [\"base\"]",
		"name":    "name = \"other\"",
	} {
		t.Run(name, func(t *testing.T) {
			profiles := fstest.MapFS{"p.toml": file(""), LocalFile("p"): file(local)}
			modules := fstest.MapFS{"base.toml": file("")}
			if _, err := loader(profiles, modules).Load("p"); err == nil || !strings.Contains(err.Error(), "belong in the profile itself") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestNamesListsOnlyProfileFiles(t *testing.T) {
	profiles := fstest.MapFS{
		"a.toml":       file(""),
		"a.local.toml": file(""),
		"README":       file(""),
		"dir.toml/x":   file(""),
	}
	names, err := loader(profiles, fstest.MapFS{}).Names()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names, []string{"a"}) {
		t.Fatalf("names = %q", names)
	}
}

func TestNixDaemonFollowsTheLastLayer(t *testing.T) {
	modules := fstest.MapFS{"nix.toml": file("[nix]\ndaemon = true")}
	if p := mustLoad(t, "modules = [\"nix\"]", modules); !p.NixDaemon {
		t.Error("the module grants the nix daemon")
	}
	if p := mustLoad(t, "modules = [\"nix\"]\n[nix]\ndaemon = false", modules); p.NixDaemon {
		t.Error("the profile takes the nix daemon away again")
	}
}

func TestLaterMountReplacesTheFirst(t *testing.T) {
	modules := fstest.MapFS{"rw.toml": file("[[mounts]]\npath = \"/x\"\nmode = \"write\"")}
	p := mustLoad(t, "modules = [\"rw\"]\n[[mounts]]\npath = \"/x\"", modules)
	if len(p.Mounts) != 1 || p.Mounts[0].Mode != ModeRead {
		t.Fatalf("mounts = %+v", p.Mounts)
	}
}

func TestModuleIncludedTwiceDoesNotStopLaterModules(t *testing.T) {
	modules := fstest.MapFS{
		"a.toml": file("modules = [\"b\"]"),
		"b.toml": file(""),
		"c.toml": file("[egress]\nallow = [\"c.example\"]"),
	}
	if p := mustLoad(t, "modules = [\"a\", \"b\", \"c\"]", modules); !p.AllowsHost("c.example") {
		t.Fatal("module c was skipped")
	}
}

func TestLaterHTTPLayerKeepsTheDefault(t *testing.T) {
	modules := fstest.MapFS{"gh.toml": file("[[http]]\nhost = \"api.github.com\"\ndefault = \"deny\"")}
	p := mustLoad(t, `
modules = ["gh"]

[[http]]
host = "api.github.com"

[[http.rules]]
method = "GET"
path = "/user"
action = "allow"
`, modules)
	h, ok := p.Intercepted("api.github.com")
	if !ok || h.Default != ActionDeny {
		t.Fatalf("default = %q", h.Default)
	}
}

func TestDecideMatchesMethodAndPath(t *testing.T) {
	h := HTTPHost{Default: ActionAllow, Rules: []Rule{
		{Method: "PUT", Path: "/repos/*/*/pulls/*/merge", Action: ActionDeny},
		{Method: "*", Path: "/admin/**", Action: ActionDeny},
	}}
	cases := []struct {
		method, path string
		want         Action
	}{
		{"PUT", "/repos/a/b/pulls/1/merge", ActionDeny},
		{"PUT", "/repos/a/b/pulls/1/merge/", ActionDeny},
		{"GET", "/repos/a/b/pulls/1/merge", ActionAllow},
		{"PUT", "/repos/a/b/pulls/1", ActionAllow},
		{"DELETE", "/admin/users", ActionDeny},
	}
	for _, c := range cases {
		if r, _ := h.Decide(c.method, c.path, nil); r.Action != c.want {
			t.Errorf("%s %s: %q, want %q", c.method, c.path, r.Action, c.want)
		}
	}
}

func TestBodyRuleSeesEscapedJSON(t *testing.T) {
	h := HTTPHost{Default: ActionAllow, Rules: []Rule{
		{Method: "POST", Path: "/graphql", BodyContains: []string{"mergePullRequest"}, Action: ActionDeny},
	}}
	body := []byte(`{"query":"mutation { \u006dergePullRequest(input:{}) { x } }"}`)
	if r, _ := h.Decide("POST", "/graphql", body); r.Action != ActionDeny {
		t.Fatalf("escaped mutation got %q", r.Action)
	}
}

func TestNeedsBodyOnlyForBodyRules(t *testing.T) {
	graphql := HTTPHost{Rules: []Rule{{Method: "POST", Path: "/graphql", GraphQL: &GraphQLRule{Operation: GraphQLMutation}, Action: ActionDeny}}}
	if !graphql.NeedsBody("POST", "/graphql") {
		t.Error("a GraphQL rule needs the body")
	}
	plain := HTTPHost{Rules: []Rule{{Method: "POST", Path: "/graphql", Action: ActionDeny}}}
	if plain.NeedsBody("POST", "/graphql") {
		t.Error("a rule without body conditions does not need the body")
	}
}

func TestPathRuleCredentialDoesNotHideNameRule(t *testing.T) {
	c := Credential{Binaries: []string{"/home/u/bin/tool", "gh"}}
	if !c.AllowsBinary("/nix/store/abc-gh-2.76/bin/gh") {
		t.Fatal("gh is listed after a path")
	}
}
