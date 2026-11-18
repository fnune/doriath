package gemini

import (
	"encoding/json"
	"path/filepath"

	"github.com/fnune/doriath/internal/agents"
	"github.com/fnune/doriath/internal/profile"
)

type Adapter struct{}

func (Adapter) Name() string { return "gemini" }

func (Adapter) Command() string { return "gemini" }

func (Adapter) Matches(argv []string) bool {
	return len(argv) > 0 && filepath.Base(argv[0]) == "gemini"
}

var seededSettings = []string{"ui", "model", "general", "context", "ide"}

func (Adapter) Seeds(s agents.Session) []agents.Seed {
	private := s.HostPath(filepath.Join(s.Home, ".gemini"))
	if private == "" {
		return nil
	}
	return []agents.Seed{{Source: filepath.Join(s.Home, ".gemini", "settings.json"), Dest: filepath.Join(private, "settings.json"), Keys: seededSettings}}
}

func (Adapter) Start(s agents.Session, argv []string) ([]string, map[string]string, error) {
	data, err := Settings(s.Profile.MCP)
	if err != nil {
		return nil, nil, err
	}
	path, err := s.WriteFile("gemini-settings.json", data)
	if err != nil {
		return nil, nil, err
	}
	return argv, map[string]string{"GEMINI_CLI_SYSTEM_SETTINGS_PATH": path}, nil
}

func (Adapter) End(agents.Session) error { return nil }

type mcpServer struct {
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	URL     string            `json:"url,omitempty"`
	Type    string            `json:"type,omitempty"`
}

func Settings(servers []profile.MCPServer) ([]byte, error) {
	mcp := map[string]mcpServer{}
	for _, s := range servers {
		if s.URL != "" {
			mcp[s.Name] = mcpServer{URL: s.URL, Type: "http"}
			continue
		}
		mcp[s.Name] = mcpServer{Command: s.Command[0], Args: s.Command[1:], Env: s.Env}
	}
	out, err := json.MarshalIndent(map[string]any{
		"mcpServers": mcp,
		"privacy":    map[string]bool{"usageStatisticsEnabled": false},
		"general":    map[string]bool{"enableAutoUpdate": false, "enableAutoUpdateNotification": false},
	}, "", "  ")
	return append(out, '\n'), err
}
