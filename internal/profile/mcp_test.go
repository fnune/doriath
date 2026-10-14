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
	if !ok || notion.Credential == nil || notion.Credential.Secret != "notion" || notion.Credential.Scheme != SchemeBearer || notion.Default != ActionAllow {
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
