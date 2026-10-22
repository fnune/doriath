package codex

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/fnune/doriath/internal/agents"
	"github.com/fnune/doriath/internal/profile"
)

func TestTheSessionConfigKeepsYourPreferencesAndDropsYourServers(t *testing.T) {
	own := []byte(`model = "gpt-6"
approval_policy = "untrusted"
notify = ["notify-send"]

[mcp_servers.yours]
command = "secret-server"

[projects."/home/u/app"]
trust_level = "trusted"

[tui]
notifications = true
`)
	s := agents.Session{Cwd: "/home/u/app", Instructions: "You run in a jail.", Profile: &profile.Profile{MCP: []profile.MCPServer{
		{Name: "local", Command: []string{"bazel-mcp", "--stdio"}, Env: map[string]string{"A": "1"}},
		{Name: "remote", URL: "https://mcp.example.com/mcp"},
	}}}
	data, err := Config(own, s)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if _, err := toml.Decode(string(data), &got); err != nil {
		t.Fatalf("%v:\n%s", err, data)
	}
	for k, want := range map[string]any{"model": "gpt-6", "approval_policy": "untrusted", "sandbox_mode": "danger-full-access", "developer_instructions": "You run in a jail."} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k], want)
		}
	}
	if _, ok := got["notify"]; ok {
		t.Error("your notify command came along")
	}
	trust := got["projects"].(map[string]any)["/home/u/app"].(map[string]any)["trust_level"]
	if trust != "untrusted" {
		t.Errorf("the project's .codex layer would load: trust_level = %v", trust)
	}
	servers := got["mcp_servers"].(map[string]any)
	if _, ok := servers["yours"]; ok || len(servers) != 2 {
		t.Errorf("servers = %v", servers)
	}
	local := servers["local"].(map[string]any)
	if local["command"] != "bazel-mcp" || local["args"].([]any)[0] != "--stdio" || servers["remote"].(map[string]any)["url"] != "https://mcp.example.com/mcp" {
		t.Errorf("servers = %v", servers)
	}
}

func TestWithoutYourConfigCodexAsksWhenItNeeds(t *testing.T) {
	data, err := Config(nil, agents.Session{Cwd: "/w", Profile: &profile.Profile{}})
	if err != nil || !strings.Contains(string(data), `approval_policy = "on-request"`) || strings.Contains(string(data), "mcp_servers") {
		t.Fatalf("%v:\n%s", err, data)
	}
}

func TestPermissionPromptsGoToDoriath(t *testing.T) {
	data, err := Hooks(90 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Command string
				Timeout int
			}
		}
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	h := got.Hooks["PermissionRequest"][0].Hooks[0]
	if h.Command != "/run/doriath-bin/doriath __hook codex permission-request --timeout 1m30s" || h.Timeout != 120 {
		t.Errorf("hook = %+v", h)
	}
}
