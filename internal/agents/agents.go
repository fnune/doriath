// Package agents adapts coding agents to girdle where profile data cannot:
// an agent's permission prompts reach girdle's approvals, and its
// transcripts come back to your own configuration. Everything else about
// an agent, such as its state, config, hosts and credentials, is an
// ordinary module.
package agents

import (
	"encoding/json"

	"github.com/fnune/girdle/internal/profile"
)

type Session struct {
	Profile *profile.Profile
	Home    string
	Cwd     string
	// HostPath returns where a path in the jail lives on the host when a
	// profile cache backs it, or "" when nothing outside the jail keeps it.
	HostPath func(jailPath string) string
	// WriteFile puts a file into the session's directory, which the jail
	// sees read-only, and returns its path in the jail.
	WriteFile func(name string, data []byte) (string, error)
	// MCPConfig is the jail's path to the profile's MCP servers in the
	// common mcpServers format, or "" when the profile names none.
	MCPConfig string
}

type Adapter interface {
	Matches(argv []string) bool
	// Start runs before the jail starts and returns the command to run
	// and the environment it adds.
	Start(s Session, argv []string) ([]string, map[string]string, error)
	// End runs after the session ends.
	End(s Session) error
}

type mcpServer struct {
	Type    string            `json:"type,omitempty"`
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	URL     string            `json:"url,omitempty"`
}

// MCPConfig writes the profile's MCP servers in the mcpServers format that
// Claude Code, Cursor and others read. A remote server carries no token: the
// proxy adds it.
func MCPConfig(servers []profile.MCPServer) ([]byte, error) {
	out := map[string]map[string]mcpServer{"mcpServers": {}}
	for _, s := range servers {
		if s.URL != "" {
			out["mcpServers"][s.Name] = mcpServer{Type: "http", URL: s.URL}
			continue
		}
		out["mcpServers"][s.Name] = mcpServer{Command: s.Command[0], Args: s.Command[1:], Env: s.Env}
	}
	data, err := json.MarshalIndent(out, "", "  ")
	return append(data, '\n'), err
}
