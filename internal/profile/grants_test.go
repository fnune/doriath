package profile

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

func grantsOf(t *testing.T, body string) []string {
	t.Helper()
	p, err := loader(fstest.MapFS{"app.toml": file(body)}, fstest.MapFS{}).Load("app")
	if err != nil {
		t.Fatal(err)
	}
	g, err := p.Grants()
	if err != nil {
		t.Fatal(err)
	}
	return g
}

const (
	grantsHead = `description = "the app"

[egress]
allow = ["a.example"]

[[mounts]]
path = "/home/u/notes"

[secrets.token]
command = ["pass", "token"]

[[http]]
host = "api.example"
`
	denyAdmin = `
[[http.rules]]
method = "*"
path = "/admin/**"
action = "deny"
`
	allowReads = `
[[http.rules]]
method = "GET"
path = "/**"
action = "allow"
`
	grantsBase = grantsHead + denyAdmin + allowReads
)

func TestGrantsAddALineForEachWiderSetting(t *testing.T) {
	base := grantsOf(t, grantsBase)
	for _, tc := range []struct{ name, from, to, want string }{
		{"a host", `allow = ["a.example"]`, `allow = ["a.example", "b.example"]`, "Egress.Allow: b.example"},
		{"a writable mount", `path = "/home/u/notes"`, "path = \"/home/u/notes\"\nmode = \"write\"", "Mounts[/home/u/notes].Mode: write"},
		{"a secret command", `command = ["pass", "token"]`, `command = ["sh", "-c", "curl evil.example"]`, "Secrets.token.Command: curl evil.example"},
		{"a cache", `[secrets.token]`, "[[caches]]\npath = \"~/.cache/x\"\n\n[secrets.token]", "Caches[/home/u/.cache/x]"},
		{"a laxer rule", `action = "deny"`, `action = "allow"`, `HTTP[api.example].Rules: {"Action":"allow","Method":"*","Path":"/admin/**"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			added := Added(base, grantsOf(t, strings.Replace(grantsBase, tc.from, tc.to, 1)))
			if !slices.Contains(added, tc.want) {
				t.Errorf("added = %q, want %q in it", added, tc.want)
			}
		})
	}
}

func TestRulesInANewOrderAreAGrant(t *testing.T) {
	added := Added(grantsOf(t, grantsBase), grantsOf(t, grantsHead+allowReads+denyAdmin))
	if len(added) != 1 || !strings.HasPrefix(added[0], "HTTP[api.example].Rules"+OrderSuffix) {
		t.Fatalf("added = %q: the first rule that matches wins, so a new order must ask", added)
	}
}

func TestLessAccessAddsNoGrant(t *testing.T) {
	narrower := strings.Replace(grantsBase, `allow = ["a.example"]`, `allow = []`, 1)
	if added := Added(grantsOf(t, grantsBase), grantsOf(t, narrower)); len(added) != 0 {
		t.Fatalf("added = %q", added)
	}
}

func TestNamesAndDescriptionsAreNotGrants(t *testing.T) {
	renamed := strings.Replace(grantsBase, `description = "the app"`, `description = "renamed"`, 1)
	if added := Added(grantsOf(t, grantsBase), grantsOf(t, renamed)); len(added) != 0 {
		t.Fatalf("added = %q", added)
	}
}

func TestArgumentsInANewOrderAreAGrant(t *testing.T) {
	reordered := strings.Replace(grantsBase, `command = ["pass", "token"]`, `command = ["token", "pass"]`, 1)
	added := Added(grantsOf(t, grantsBase), grantsOf(t, reordered))
	if len(added) != 1 || !strings.HasPrefix(added[0], "Secrets.token.Command"+OrderSuffix) {
		t.Fatalf("added = %q: the same arguments in a new order run another command", added)
	}
}
