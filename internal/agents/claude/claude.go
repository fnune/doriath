// Package claude adapts Claude Code to the jail: its settings, its state
// directory and its hooks.
package claude

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/fnune/girdle/internal/jail"
	"github.com/fnune/girdle/internal/profile"
)

func Matches(argv []string) bool {
	return len(argv) > 0 && filepath.Base(argv[0]) == "claude"
}

// Args adds girdle's settings file and drops the project and local settings
// sources, which the agent could otherwise edit to widen its own rules. The
// project's checked-in settings are merged into the settings file instead,
// as they were when the session started.
func Args(argv []string, settingsPath string) []string {
	out := []string{argv[0], "--settings", settingsPath, "--setting-sources", "user"}
	return append(out, argv[1:]...)
}

type Files interface {
	ReadFile(path string) ([]byte, error)
}

type settings struct {
	DisableClaudeAiConnectors bool              `json:"disableClaudeAiConnectors,omitempty"`
	StatusLine                *statusLine       `json:"statusLine,omitempty"`
	DeniedMcpServers          []deniedServer    `json:"deniedMcpServers,omitempty"`
	Permissions               permissions       `json:"permissions"`
	Hooks                     map[string][]any  `json:"hooks"`
	Env                       map[string]string `json:"env,omitempty"`
}

type statusLine struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

type deniedServer struct {
	ServerName string `json:"serverName"`
}

type permissions struct {
	Allow []string `json:"allow,omitempty"`
	Ask   []string `json:"ask,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

type hookGroup struct {
	Matcher string        `json:"matcher,omitempty"`
	Hooks   []hookCommand `json:"hooks"`
}

type hookCommand struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

type projectSettings struct {
	Permissions permissions       `json:"permissions"`
	Hooks       map[string][]any  `json:"hooks"`
	Env         map[string]string `json:"env"`
}

var hookTimeoutMargin = 30 * time.Second

// Settings builds the settings file for one session. Project rules and hooks
// come from the repo's settings files as they are now, so later edits by the
// agent have no effect until the next session.
func Settings(p *profile.Profile, cwd string, files Files) ([]byte, error) {
	s := settings{
		DisableClaudeAiConnectors: p.Claude.DisableConnectors,
		Permissions:               permissions{Ask: slices.Clone(p.Claude.Ask), Deny: slices.Clone(p.Claude.Deny)},
		Hooks:                     map[string][]any{},
	}
	for _, name := range p.Claude.DeniedMCPServers {
		s.DeniedMcpServers = append(s.DeniedMcpServers, deniedServer{ServerName: name})
	}
	for _, name := range []string{"settings.json", "settings.local.json"} {
		ps, err := readProject(files, filepath.Join(cwd, ".claude", name))
		if err != nil {
			return nil, err
		}
		s.Permissions.Allow = append(s.Permissions.Allow, ps.Permissions.Allow...)
		s.Permissions.Ask = append(s.Permissions.Ask, ps.Permissions.Ask...)
		s.Permissions.Deny = append(s.Permissions.Deny, ps.Permissions.Deny...)
		for event, groups := range ps.Hooks {
			s.Hooks[event] = append(s.Hooks[event], groups...)
		}
		for k, v := range ps.Env {
			if s.Env == nil {
				s.Env = map[string]string{}
			}
			s.Env[k] = v
		}
	}
	timeout := int((p.Claude.ApprovalTimeout + hookTimeoutMargin) / time.Second)
	s.Hooks["PermissionRequest"] = append(s.Hooks["PermissionRequest"], hookGroup{
		Matcher: "*",
		Hooks: []hookCommand{{
			Type:    "command",
			Command: fmt.Sprintf("%s hook claude permission-request --timeout %s", jail.ExePath, p.Claude.ApprovalTimeout),
			Timeout: timeout,
		}},
	})
	s.Hooks["SessionStart"] = append(s.Hooks["SessionStart"], hookGroup{
		Hooks: []hookCommand{{Type: "command", Command: jail.ExePath + " hook claude session-start", Timeout: 10}},
	})
	if p.Claude.StatusLine {
		s.StatusLine = &statusLine{Type: "command", Command: jail.ExePath + " statusline"}
	}
	s.Hooks["Notification"] = append(s.Hooks["Notification"], hookGroup{
		Hooks: []hookCommand{{Type: "command", Command: jail.ExePath + " hook claude notification", Timeout: 10}},
	})
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode Claude settings: %w", err)
	}
	return append(out, '\n'), nil
}

func readProject(files Files, path string) (projectSettings, error) {
	data, err := files.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return projectSettings{}, nil
	}
	if err != nil {
		return projectSettings{}, fmt.Errorf("read %s: %w", path, err)
	}
	var ps projectSettings
	if err := json.Unmarshal(data, &ps); err != nil {
		return projectSettings{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return ps, nil
}

// ProjectDir is how Claude Code names a working directory under
// ~/.claude/projects.
func ProjectDir(cwd string) string {
	return nonAlnum.ReplaceAllString(cwd, "-")
}

var nonAlnum = regexp.MustCompile(`[^A-Za-z0-9]`)

// State describes how the jail sees Claude's state. The jail's ~/.claude is a
// directory that belongs to the profile, so nothing the agent writes there
// reaches the desktop's Claude, which runs hooks, plugins and settings from
// the real ~/.claude outside any jail. Into it go, read-only, the files that
// configure Claude. This project's directory is copied in, and only its
// transcripts are copied back, so memory files the agent writes never reach
// desktop sessions. The profile keeps its own claude.ai login unless it shares
// the desktop's.
type State struct {
	Home       string
	Cwd        string
	ShareLogin bool
	// Private is the profile's own ~/.claude.
	Private string
	// ConfigCopy is a copy of ~/.claude.json made at session start.
	ConfigCopy string
}

var shared = []string{
	"CLAUDE.md", "agents", "chrome", "commands", "hooks", "keybindings.json", "output-styles",
	"plugins", "settings.json", "skills", "statusline.sh",
}

const credentials = ".credentials.json"

// Host resolves symlinks, because bubblewrap cannot mount on a symlink and
// home-manager links these files into the nix store.
type Host interface {
	Kind(path string) string
	Resolve(path string) (string, error)
}

func (st State) Binds(host Host) []jail.Bind {
	real := filepath.Join(st.Home, ".claude")
	binds := []jail.Bind{{Source: st.Private, Dest: real}}
	if st.ConfigCopy != "" {
		binds = append(binds, jail.Bind{Source: st.ConfigCopy, Dest: filepath.Join(st.Home, ".claude.json")})
	}
	for _, name := range shared {
		src := filepath.Join(real, name)
		if host.Kind(src) == "" {
			continue
		}
		target, err := host.Resolve(src)
		if err != nil {
			continue
		}
		binds = append(binds, jail.Bind{Source: target, Dest: filepath.Join(real, name), ReadOnly: true})
	}
	if cred := filepath.Join(real, credentials); st.ShareLogin && host.Kind(cred) == "file" {
		binds = append(binds, jail.Bind{Source: cred, Dest: cred})
	}
	return binds
}

// Shared lists what the jail sees from the real ~/.claude, read-only.
func Shared() []string { return slices.Clone(shared) }

// FilterMCPServers keeps only the named MCP servers in a ~/.claude.json
// document, at the top level and per project. Other keys are left as they
// are. Servers in your own configuration reach hosts and tools the profile
// was not written for, so a profile names the ones it wants; the rest stay
// out of the jail.
func FilterMCPServers(data []byte, keep []string) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse ~/.claude.json: %w", err)
	}
	filter := func(raw json.RawMessage) (json.RawMessage, error) {
		var servers map[string]json.RawMessage
		if err := json.Unmarshal(raw, &servers); err != nil {
			return nil, err
		}
		for name := range servers {
			if !slices.Contains(keep, name) {
				delete(servers, name)
			}
		}
		return json.Marshal(servers)
	}
	if raw, ok := doc["mcpServers"]; ok {
		filtered, err := filter(raw)
		if err != nil {
			return nil, fmt.Errorf("parse mcpServers: %w", err)
		}
		doc["mcpServers"] = filtered
	}
	if raw, ok := doc["projects"]; ok {
		var projects map[string]map[string]json.RawMessage
		if err := json.Unmarshal(raw, &projects); err != nil {
			return nil, fmt.Errorf("parse projects: %w", err)
		}
		for name, proj := range projects {
			if servers, ok := proj["mcpServers"]; ok {
				filtered, err := filter(servers)
				if err != nil {
					return nil, fmt.Errorf("parse mcpServers of %s: %w", name, err)
				}
				proj["mcpServers"] = filtered
			}
		}
		out, err := json.Marshal(projects)
		if err != nil {
			return nil, err
		}
		doc["projects"] = out
	}
	return json.Marshal(doc)
}

// SessionStart is the hook output that adds context for the agent.
func SessionStart(context string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"hookSpecificOutput": map[string]string{
			"hookEventName":     "SessionStart",
			"additionalContext": context,
		},
	})
}
