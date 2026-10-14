//go:build integration

package session_test

import (
	"strings"
	"testing"
)

// TestRemoteMCPServerGetsItsTokenAtTheProxy lists a remote MCP server whose
// token girdle adds on the way out: the jail sees the server, never the token.
func TestRemoteMCPServerGetsItsTokenAtTheProxy(t *testing.T) {
	e := newEnv(t)
	p := e.profile("\n[[mcp]]\nname = \"remote\"\nurl = \"https://example.com/mcp\"\nsecret = \"github\"\n\n[[mcp]]\nname = \"local\"\ncommand = [\"true\"]\n")
	code, out := e.run(p, `
grep -q '"url": "https://example.com/mcp"' /run/girdle/mcp.json || echo "FAIL no remote server in the config"
grep -q '"command": "true"' /run/girdle/mcp.json || echo "FAIL no local server in the config"
grep -rq real-token /run/girdle/ 2>/dev/null && echo "FAIL the token is in the jail"
curl -sS -o /dev/null -w "mcp %{http_code}\n" -X POST -d '{"jsonrpc":"2.0"}' https://example.com/mcp
`, nil)
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "mcp 200") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if req := e.upstream.find("/mcp"); req == nil || req.Header.Get("Authorization") != "Bearer real-token" {
		t.Fatalf("upstream request: %+v", req)
	}
}
