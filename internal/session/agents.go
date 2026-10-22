package session

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/fnune/doriath/internal/agents"
	"github.com/fnune/doriath/internal/agents/claude"
	"github.com/fnune/doriath/internal/jail"
	"github.com/fnune/doriath/internal/profile"
)

var adapters = []agents.Adapter{claude.Adapter{}}

const mcpConfigFile = "mcp.json"

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

func AdapterNamed(name string) agents.Adapter {
	for _, a := range adapters {
		if a.Name() == name {
			return a
		}
	}
	return nil
}

func (s *Session) writeInstructions() error {
	text := s.status().Describe()
	for i, path := range s.req.Profile.Agent.Instructions {
		own, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("read your instructions %s: %w", path, err)
		}
		name := fmt.Sprintf("instructions-%d.md", i)
		if err := writeFile(s.jailPath(name), withSession(own, text), 0o644); err != nil {
			return err
		}
		s.instructions = append(s.instructions, jail.Bind{Source: s.jailPath(name), Dest: path, ReadOnly: true})
	}
	return nil
}

func withSession(own []byte, session string) []byte {
	own = bytes.TrimRight(own, "\n")
	if len(own) == 0 {
		return []byte(session)
	}
	return append(append(own, "\n\n"...), session...)
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
