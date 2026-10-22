package gemini

import (
	"encoding/json"
	"testing"

	"github.com/fnune/doriath/internal/profile"
)

func TestSettingsCarryTheProfilesServersAndTurnOffStatistics(t *testing.T) {
	data, err := Settings([]profile.MCPServer{
		{Name: "local", Command: []string{"bazel-mcp", "--stdio"}},
		{Name: "remote", URL: "https://mcp.example.com/mcp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		MCPServers map[string]mcpServer `json:"mcpServers"`
		Privacy    map[string]bool
		General    map[string]bool
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if l := got.MCPServers["local"]; l.Command != "bazel-mcp" || len(l.Args) != 1 {
		t.Errorf("local = %+v", l)
	}
	if r := got.MCPServers["remote"]; r.URL != "https://mcp.example.com/mcp" || r.Type != "http" {
		t.Errorf("remote = %+v", r)
	}
	if got.Privacy["usageStatisticsEnabled"] || got.General["enableAutoUpdate"] {
		t.Errorf("settings = %s", data)
	}
}
