package agents

import (
	"encoding/json"
	"testing"

	"github.com/fnune/girdle/internal/profile"
)

func TestMCPConfig(t *testing.T) {
	data, err := MCPConfig([]profile.MCPServer{
		{Name: "bazel", Command: []string{"bazel-mcp", "--stdio"}, Env: map[string]string{"A": "1"}},
		{Name: "notion", URL: "https://mcp.notion.com/mcp", Secret: "notion"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		MCPServers map[string]map[string]any `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	bazel, notion := got.MCPServers["bazel"], got.MCPServers["notion"]
	if bazel["command"] != "bazel-mcp" || bazel["args"].([]any)[0] != "--stdio" || notion["type"] != "http" || notion["url"] != "https://mcp.notion.com/mcp" {
		t.Fatalf("%s", data)
	}
	if _, ok := notion["headers"]; ok {
		t.Fatal("the token is the proxy's to add, never the agent's")
	}
}
