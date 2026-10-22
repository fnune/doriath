package session

import (
	"fmt"
	"path/filepath"
	"slices"

	"github.com/fnune/doriath/internal/agents"
	"github.com/fnune/doriath/internal/agents/claude"
	"github.com/fnune/doriath/internal/jail"
	"github.com/fnune/doriath/internal/profile"
)

// adapters are the agents doriath supports beyond what their modules give
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

func adapterFor(p *profile.Profile, argv []string) (agents.Adapter, string) {
	for _, a := range adapters {
		if !a.Matches(argv) {
			continue
		}
		if slices.Contains(p.Modules, a.Name()) {
			return a, ""
		}
		return nil, fmt.Sprintf("%s runs without doriath's %s adapter, because profile %s does not list the %s module. Add the module for the agent's settings, approvals and transcripts.", argv[0], a.Name(), p.Name, a.Name())
	}
	return nil, ""
}

// AgentCommand is the command of the agent whose module the profile lists,
// for a project's direnv shim.
func AgentCommand(p *profile.Profile) (string, error) {
	var found []agents.Adapter
	for _, a := range adapters {
		if slices.Contains(p.Modules, a.Name()) {
			found = append(found, a)
		}
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("profile %s lists no agent module doriath has an adapter for; name the command with --command", p.Name)
	case 1:
		return found[0].Command(), nil
	}
	return "", fmt.Errorf("profile %s lists several agent modules; name the command with --command", p.Name)
}

func (s *Session) agentSession() agents.Session {
	home := s.deps.Paths.Home
	mcp := ""
	if len(s.req.Profile.MCP) > 0 {
		mcp = jail.InJail(mcpConfigFile)
	}
	return agents.Session{
		Titled:    s.titled,
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
