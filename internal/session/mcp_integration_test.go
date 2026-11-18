//go:build integration

package session_test

import (
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/approval"
)

func TestRemoteMCPServerGetsItsTokenAtTheProxy(t *testing.T) {
	e := newEnv(t)
	p := e.profile("\n[[mcp]]\nname = \"remote\"\nurl = \"https://example.com/mcp\"\nsecret = \"github\"\n\n[[mcp]]\nname = \"local\"\ncommand = [\"true\"]\n")
	code, out := e.run(p, `
grep -q '"url": "https://example.com/mcp"' /run/doriath/mcp.json || echo "FAIL no remote server in the config"
grep -q '"command": "true"' /run/doriath/mcp.json || echo "FAIL no local server in the config"
grep -rq real-token /run/doriath/ 2>/dev/null && echo "FAIL the token is in the jail"
curl -sS -o /dev/null -w "mcp %{http_code}\n" -X POST -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' https://example.com/mcp
`, nil)
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "mcp 200") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if req := e.upstream.find("/mcp"); req == nil || req.Header.Get("Authorization") != "Bearer real-token" {
		t.Fatalf("upstream request: %+v", req)
	}
}

func TestMCPToolIsHeldForApproval(t *testing.T) {
	e := newEnv(t)
	p := e.profile("\n[[mcp]]\nname = \"remote\"\nurl = \"https://example.com/mcp\"\napprove = [\"create-*\"]\n")
	var req approval.Request
	code, out := e.run(p, `
call() { curl -sS -o /dev/null -w "$1 %{http_code}\n" -X POST -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"'$1'"}}' https://example.com/mcp; }
call search
call create-page
`, func() {
		req = e.decideNext(approval.Decision{Verdict: approval.VerdictDeny, By: "test"})
	})
	if code != 0 || !strings.Contains(out, "search 200") || !strings.Contains(out, "create-page 403") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if req.Summary != "Call remote tool create-page" {
		t.Errorf("summary = %q", req.Summary)
	}
}
