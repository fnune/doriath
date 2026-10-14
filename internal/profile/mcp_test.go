package profile

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestMCPServers(t *testing.T) {
	p := mustLoad(t, `
[secrets.notion]
command = ["rbw", "get", "notion"]

[[mcp]]
name = "bazel"
command = ["bazel-mcp", "--stdio"]
env = { BAZEL = "1" }

[[mcp]]
name = "notion"
url = "https://mcp.notion.com/mcp"
secret = "notion"

[[mcp]]
name = "docs"
url = "https://docs.example.com/mcp"
`, nil)
	if len(p.MCP) != 3 || p.MCP[0].Command[0] != "bazel-mcp" || p.MCP[1].Secret != "notion" {
		t.Fatalf("mcp = %+v", p.MCP)
	}
	notion, ok := p.Intercepted("mcp.notion.com")
	if !ok || notion.Credential == nil || notion.Credential.Secret != "notion" || notion.Credential.Scheme != SchemeBearer || notion.Default != ActionApprove {
		t.Errorf("a remote server with a secret is intercepted and gets its token at the proxy: %+v", notion)
	}
	if _, ok := p.Intercepted("docs.example.com"); ok || !p.AllowsHost("docs.example.com") {
		t.Error("a remote server without a secret is a plain egress host")
	}
}

func TestMCPServerKeepsTheProfilesRulesForItsHost(t *testing.T) {
	p := mustLoad(t, `
[secrets.notion]
file = "/t"

[[http]]
host = "mcp.notion.com"
default = "approve"

[[mcp]]
name = "notion"
url = "https://mcp.notion.com/mcp"
secret = "notion"
`, nil)
	h, _ := p.Intercepted("mcp.notion.com")
	if h.Default != ActionApprove || h.Credential == nil {
		t.Fatalf("host = %+v", h)
	}
}

func TestLaterMCPServerReplacesTheFirst(t *testing.T) {
	modules := fstest.MapFS{"m.toml": file("[[mcp]]\nname = \"x\"\ncommand = [\"old\"]")}
	p := mustLoad(t, "modules = [\"m\"]\n[[mcp]]\nname = \"x\"\ncommand = [\"new\"]", modules)
	if len(p.MCP) != 1 || p.MCP[0].Command[0] != "new" {
		t.Fatalf("mcp = %+v", p.MCP)
	}
}

func TestMCPServerErrors(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"no name":        {"[[mcp]]\ncommand = [\"x\"]", "name it"},
		"both":           {"[[mcp]]\nname = \"x\"\ncommand = [\"x\"]\nurl = \"https://a.example/\"", "not both"},
		"neither":        {"[[mcp]]\nname = \"x\"", "set command or url"},
		"plain http":     {"[[mcp]]\nname = \"x\"\nurl = \"http://a.example/\"", "https"},
		"other port":     {"[[mcp]]\nname = \"x\"\nurl = \"https://a.example:8443/\"", "https"},
		"local secret":   {"[[mcp]]\nname = \"x\"\ncommand = [\"x\"]\nsecret = \"s\"", "remote servers"},
		"missing secret": {"[[mcp]]\nname = \"x\"\nurl = \"https://a.example/\"\nsecret = \"nope\"", "[secrets.nope]"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := load(t, tc.body, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestMCPToolCalls(t *testing.T) {
	for body, want := range map[string]string{
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create-page"}}`:                                               "create-page",
		`[{"method":"tools/call","params":{"name":"a"}},{"method":"tools/list"},{"method":"tools/call","params":{"name":"b"}}]`: "a, b",
		`{"method":"initialize"}`: "",
		`not json`:                "",
	} {
		if got := DescribeMCP([]byte(body)); got != want {
			t.Errorf("%s: %q, want %q", body, got, want)
		}
	}
}

func TestMCPToolHolds(t *testing.T) {
	p := mustLoad(t, `
[[mcp]]
name = "notion"
url = "https://mcp.notion.com/mcp"
default = "approve"
allow = ["notion-search", "notion-fetch"]
deny = ["notion-delete-*"]
`, nil)
	h, ok := p.Intercepted("mcp.notion.com")
	if !ok || h.Credential != nil || h.Default != ActionApprove {
		t.Fatalf("holds without a secret still intercept the host, without a credential: %+v", h)
	}
	call := func(names ...string) string {
		var parts []string
		for _, n := range names {
			parts = append(parts, `{"method":"tools/call","params":{"name":"`+n+`"}}`)
		}
		return "[" + strings.Join(parts, ",") + "]"
	}
	for body, want := range map[string]Action{
		call("notion-search"):                       ActionAllow,
		call("notion-search", "notion-fetch"):       ActionAllow,
		call("notion-create-pages"):                 ActionApprove,
		call("notion-search", "notion-create-x"):    ActionApprove,
		call("notion-search", "notion-delete-page"): ActionDeny,
		`{"method":"tools/list"}`:                   ActionAllow,
		`not json-rpc`:                              ActionApprove,
		`[{"method":"tools/list"}, 1]`:              ActionApprove,
	} {
		if r, _ := h.DecideRequest("POST", "/mcp", nil, []byte(body)); r.Action != want {
			t.Errorf("%s: %s, want %s", body, r.Action, want)
		}
	}
	if r, _ := h.DecideRequest("POST", "/sse", nil, []byte(call("notion-create-pages"))); r.Action != ActionApprove {
		t.Errorf("a tool call on another path of the host must be held too: %s", r.Action)
	}
	if r, _ := h.DecideRequest("POST", "/sse", nil, []byte(call("notion-delete-x"))); r.Action != ActionDeny {
		t.Errorf("a denied tool on another path: %s", r.Action)
	}
	for _, tc := range []struct {
		method, path string
		want         Action
	}{{"GET", "/mcp", ActionAllow}, {"DELETE", "/mcp", ActionAllow}, {"GET", "/admin", ActionApprove}} {
		if r, _ := h.DecideRequest(tc.method, tc.path, nil, nil); r.Action != tc.want {
			t.Errorf("%s %s: %s, want %s", tc.method, tc.path, r.Action, tc.want)
		}
	}
	if !h.NeedsBody("POST", "/mcp") {
		t.Error("tool holds need the body")
	}
}

func TestMCPToolHoldErrors(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"local server": {"[[mcp]]\nname = \"x\"\ncommand = [\"x\"]\napprove = [\"a\"]", "need a remote server"},
		"bad default":  {"[[mcp]]\nname = \"x\"\nurl = \"https://a.example/mcp\"\ndefault = \"maybe\"", "want allow, approve or deny"},
		"bad glob":     {"[[mcp]]\nname = \"x\"\nurl = \"https://a.example/mcp\"\napprove = [\"[\"]", "glob"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := load(t, tc.body, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
