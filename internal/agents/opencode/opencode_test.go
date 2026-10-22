package opencode

import (
	"encoding/json"
	"testing"

	"github.com/fnune/doriath/internal/profile"
)

func TestConfigAddsTheProfilesServersAndTheSessionText(t *testing.T) {
	data, err := Config([]profile.MCPServer{
		{Name: "local", Command: []string{"bazel-mcp", "--stdio"}, Env: map[string]string{"A": "1"}},
		{Name: "remote", URL: "https://mcp.example.com/mcp"},
	}, []string{"/run/doriath/opencode-instructions.md"})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Autoupdate   bool
		Share        string
		Instructions []string
		MCP          map[string]mcpServer
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Autoupdate || got.Share != "disabled" || len(got.Instructions) != 1 {
		t.Errorf("config = %s", data)
	}
	if l := got.MCP["local"]; l.Type != "local" || l.Command[0] != "bazel-mcp" || l.Environment["A"] != "1" {
		t.Errorf("local = %+v", l)
	}
	if r := got.MCP["remote"]; r.Type != "remote" || r.URL != "https://mcp.example.com/mcp" {
		t.Errorf("remote = %+v", r)
	}
}
