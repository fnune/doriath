package session

import (
	"path/filepath"

	"github.com/fnune/girdle/internal/agents"
	"github.com/fnune/girdle/internal/agents/claude"
	"github.com/fnune/girdle/internal/jail"
)

// adapters are the agents girdle supports beyond what their modules give
// them. Any other command runs as is.
var adapters = []agents.Adapter{claude.Adapter{}}

const mcpConfigFile = "mcp.json"

// writeMCPConfig puts the profile's MCP servers where every agent's adapter
// can point the agent at them.
func (s *Session) writeMCPConfig() error {
	if len(s.req.Profile.MCP) == 0 {
		return nil
	}
	data, err := agents.MCPConfig(s.req.Profile.MCP)
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(s.jailDir, mcpConfigFile), data, 0o644)
}

func adapterFor(argv []string) agents.Adapter {
	for _, a := range adapters {
		if a.Matches(argv) {
			return a
		}
	}
	return nil
}

func (s *Session) agentSession() agents.Session {
	home := s.deps.Paths.Home
	mcp := ""
	if len(s.req.Profile.MCP) > 0 {
		mcp = jail.InJail(mcpConfigFile)
	}
	return agents.Session{
		MCPConfig: mcp,
		Profile:   s.req.Profile,
		Home:      home,
		Cwd:       s.req.Cwd,
		HostPath: func(p string) string {
			for _, c := range s.req.Profile.Caches {
				if c.Path == p {
					return jail.CacheSource(s.cacheRoot(), p, home)
				}
			}
			return ""
		},
		WriteFile: func(name string, data []byte) (string, error) {
			if err := writeFile(filepath.Join(s.jailDir, name), data, 0o644); err != nil {
				return "", err
			}
			return jail.InJail(name), nil
		},
	}
}
