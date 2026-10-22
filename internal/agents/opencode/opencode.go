// Package opencode adapts opencode to doriath. The opencode module gives it
// its own data, state and cache folders and your config read-only; this
// adapter adds config through OPENCODE_CONFIG_CONTENT, which overrides
// yours and the project's, with the profile's MCP servers and the session
// text. opencode's plugins cannot answer a permission prompt, so its
// prompts stay in its terminal.
package opencode

import (
	"encoding/json"
	"path/filepath"

	"github.com/fnune/doriath/internal/agents"
	"github.com/fnune/doriath/internal/profile"
)

type Adapter struct{}

func (Adapter) Name() string { return "opencode" }

func (Adapter) Command() string { return "opencode" }

func (Adapter) Matches(argv []string) bool {
	return len(argv) > 0 && filepath.Base(argv[0]) == "opencode"
}

func (Adapter) Seeds(agents.Session) []agents.Seed { return nil }

func (Adapter) End(agents.Session) error { return nil }

func (Adapter) Start(s agents.Session, argv []string) ([]string, map[string]string, error) {
	var instructions []string
	if s.Instructions != "" {
		path, err := s.WriteFile("opencode-instructions.md", []byte(s.Instructions))
		if err != nil {
			return nil, nil, err
		}
		instructions = []string{path}
	}
	data, err := Config(s.Profile.MCP, instructions)
	if err != nil {
		return nil, nil, err
	}
	return argv, map[string]string{"OPENCODE_CONFIG_CONTENT": string(data)}, nil
}

type mcpServer struct {
	Type        string            `json:"type"`
	Command     []string          `json:"command,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	URL         string            `json:"url,omitempty"`
}

// Config adds to yours: opencode joins instructions lists and merges MCP
// servers by name.
func Config(servers []profile.MCPServer, instructions []string) ([]byte, error) {
	config := map[string]any{"autoupdate": false, "share": "disabled"}
	if len(instructions) > 0 {
		config["instructions"] = instructions
	}
	if len(servers) > 0 {
		mcp := map[string]mcpServer{}
		for _, s := range servers {
			if s.URL != "" {
				mcp[s.Name] = mcpServer{Type: "remote", URL: s.URL}
				continue
			}
			mcp[s.Name] = mcpServer{Type: "local", Command: s.Command, Environment: s.Env}
		}
		config["mcp"] = mcp
	}
	return json.Marshal(config)
}
