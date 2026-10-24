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

func TestARefusedHostGivesTheJailNothing(t *testing.T) {
	before := grantsOf(t, "[egress]\nallow = [\"a.example\"]\n")
	after := grantsOf(t, "[egress]\nallow = [\"a.example\"]\ndeny = [\"b.example\"]\n")
	if added := Added(before, after); len(added) != 0 {
		t.Errorf("a refusal counts as more: %v", added)
	}
	if added := Added(after, before); len(added) != 0 {
		t.Errorf("dropping a refusal counts as more, though the host still asks: %v", added)
	}
}

func TestDroppingARestrictionIsARemovedGrant(t *testing.T) {
	const binaries = `
[[http]]
host = "cred.example"
credential = { secret = "token", binaries = ["gh"] }
only = ["cred.example"]
default = "deny"

[[http.rules]]
method = "GET"
path = "/**"
action = "approve"
`
	const claude = `
[claude]
deny = ["WebFetch"]
`
	const hidden = `
[[mounts]]
path = "/home/u/notes/.env"
mode = "hide"
`
	base := grantsOf(t, grantsBase+binaries+claude+hidden)
	for _, tc := range []struct{ name, from, to, want string }{
		{"a deny rule", denyAdmin, "", `HTTP[api.example].Rules: {"Action":"deny","Method":"*","Path":"/admin/**"}`},
		{"an approve rule", "action = \"approve\"\n", "action = \"allow\"\n", `HTTP[cred.example].Rules: {"Action":"approve","Method":"GET","Path":"/**"}`},
		{"the programs of a credential", `, binaries = ["gh"]`, "", "HTTP[cred.example].Credential.Binaries: gh"},
		{"the hosts a wildcard is limited to", "only = [\"cred.example\"]\n", "", "HTTP[cred.example].Only: cred.example"},
		{"a host default", "default = \"deny\"\n", "", "HTTP[cred.example].Default: deny"},
		{"a hidden path", hidden, "", "Mounts[/home/u/notes/.env].Mode: hide"},
		{"an agent refusal", claude, "", "Claude.Deny: WebFetch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := grantsOf(t, strings.Replace(grantsBase+binaries+claude+hidden, tc.from, tc.to, 1))
			removed := Removed(base, now)
			if !slices.Contains(removed, tc.want) {
				t.Errorf("removed = %q, want %q in it", removed, tc.want)
			}
		})
	}
}

func TestNarrowingRemovesNoRestriction(t *testing.T) {
	base := grantsOf(t, grantsBase)
	for name, narrower := range map[string]string{
		"a host":        strings.Replace(grantsBase, `allow = ["a.example"]`, `allow = []`, 1),
		"a mount":       strings.Replace(grantsBase, "[[mounts]]\npath = \"/home/u/notes\"\n", "", 1),
		"an allow rule": strings.Replace(grantsBase, allowReads, "", 1),
	} {
		if removed := Removed(base, grantsOf(t, narrower)); len(removed) != 0 {
			t.Errorf("%s: removed = %q", name, removed)
		}
	}
	if Restrictive("HTTP[api.example].Rules" + OrderSuffix + "abcd") {
		t.Error("a new order of rules is an added grant, not a removed restriction")
	}
}

func TestAProfileThatDropsAMountAsksNothing(t *testing.T) {
	mounts := "[[mounts]]\npath = \"~/a\"\n\n[[mounts]]\npath = \"~/b\"\n\n[[mounts]]\npath = \"~/c\"\n"
	fewer := strings.Replace(mounts, "[[mounts]]\npath = \"~/b\"\n\n", "", 1)
	if added := Added(grantsOf(t, mounts), grantsOf(t, fewer)); len(added) != 0 {
		t.Fatalf("added = %q: doriath binds mounts by depth, so their order gives nothing", added)
	}
}
