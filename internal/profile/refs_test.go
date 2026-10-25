package profile

import (
	"strings"
	"testing"
	"testing/fstest"
)

const agentBranches = `
[[http]]
host = "git.example.org"
default = "approve"

[[http.rules]]
method = "POST"
path = "/**/git-receive-pack"
refs = ["refs/heads/main", "refs/tags/**"]
action = "deny"

[[http.rules]]
method = "POST"
path = "/**/git-receive-pack"
refs = ["refs/heads/agent/**"]
action = "allow"
`

func decidePush(t *testing.T, h HTTPHost, push *Push) Action {
	t.Helper()
	r, _ := h.DecidePush("POST", "/o/r.git/git-receive-pack", nil, nil, nil, push)
	return r.Action
}

func TestRefRules(t *testing.T) {
	p, err := loader(fstest.MapFS{"p.toml": file(agentBranches)}, fstest.MapFS{}).Load("p")
	if err != nil {
		t.Fatal(err)
	}
	h, _ := p.Intercepted("git.example.org")
	cases := []struct {
		name string
		push *Push
		want Action
	}{
		{"agent branches only", &Push{Refs: []string{"refs/heads/agent/a", "refs/heads/agent/b/c"}}, ActionAllow},
		{"an agent branch next to another branch", &Push{Refs: []string{"refs/heads/agent/a", "refs/heads/feature"}}, ActionApprove},
		{"an agent branch next to main", &Push{Refs: []string{"refs/heads/agent/a", "refs/heads/main"}}, ActionDeny},
		{"a tag", &Push{Refs: []string{"refs/tags/v1"}}, ActionDeny},
		{"the agent prefix itself, as ** matches no segment too", &Push{Refs: []string{"refs/heads/agent"}}, ActionAllow},
		{"a branch that starts like agent", &Push{Refs: []string{"refs/heads/agents/a"}}, ActionApprove},
		{"refs that the proxy could not read", &Push{Refs: []string{"refs/heads/agent/a"}, Unread: true}, ActionDeny},
		{"no push", nil, ActionApprove},
		{"a push without refs", &Push{}, ActionApprove},
	}
	for _, c := range cases {
		if got := decidePush(t, h, c.push); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRefPatternsMustBeRefs(t *testing.T) {
	for _, pattern := range []string{"heads/agent/**", "/refs/heads/x", "refs/heads/agent-*", "refs/**/**"} {
		profiles := fstest.MapFS{"p.toml": file("[[http]]\nhost = \"a.com\"\n[[http.rules]]\npath = \"/**\"\naction = \"allow\"\nrefs = [\"" + pattern + "\"]\n")}
		if _, err := loader(profiles, fstest.MapFS{}).Load("p"); err == nil || !strings.Contains(err.Error(), "ref pattern") {
			t.Errorf("%q: %v", pattern, err)
		}
	}
}

func FuzzRefAllowCoversEveryRef(f *testing.F) {
	f.Add("refs/heads/agent/a", "refs/heads/main", false)
	f.Add("refs/heads/agent/a", "refs/heads/agent/b", false)
	f.Add("refs/heads/agent/a", "refs/heads/agent/b", true)
	f.Add("refs/heads/AGENT/a", "refs/heads/agent", false)
	allow := HTTPHost{Default: ActionApprove, Rules: []Rule{{Method: "POST", Path: "/**", Refs: []RefPattern{"refs/heads/agent/**"}, Action: ActionAllow}}}
	f.Fuzz(func(t *testing.T, a, b string, unread bool) {
		push := &Push{Refs: []string{a, b}, Unread: unread}
		if decidePush(t, allow, push) != ActionAllow {
			return
		}
		if unread {
			t.Fatal("an allow covered refs that the proxy could not read")
		}
		for _, ref := range push.Refs {
			if ref := strings.ToLower(ref); ref != "refs/heads/agent" && !strings.HasPrefix(ref, "refs/heads/agent/") {
				t.Fatalf("an allow for refs/heads/agent/** covered %q", ref)
			}
		}
	})
}
