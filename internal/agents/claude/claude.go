// Package claude adapts Claude Code to doriath. The claude module gives it a
// private ~/.claude with your configuration read-only; this adapter does
// what the module cannot: Claude's permission prompts go to doriath's
// approvals, with the project's rules frozen as they were at the start, and
// transcripts come back to your ~/.claude/projects when the session ends.
package claude

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/fnune/doriath/internal/agents"
	"github.com/fnune/doriath/internal/jail"
	"github.com/fnune/doriath/internal/profile"
)

type Adapter struct{}

func (Adapter) Name() string { return "claude" }

func (Adapter) Command() string { return "claude" }

func (Adapter) Matches(argv []string) bool {
	return len(argv) > 0 && filepath.Base(argv[0]) == "claude"
}

var seeded = []string{
	"hasCompletedOnboarding", "lastOnboardingVersion", "lastReleaseNotesSeen",
	"hasSeenTasksHint", "hasShownOpus45Notice", "hasShownOpus46Notice", "effortCalloutV2Dismissed",
	"migrationVersion", "opus45MigrationComplete", "opusProMigrationComplete",
	"sonnet45MigrationComplete", "sonnet1m45MigrationComplete", "thinkingMigrationComplete",
}

func (Adapter) Seeds(s agents.Session) []agents.Seed {
	private := s.HostPath(filepath.Join(s.Home, ".claude"))
	if private == "" {
		return nil
	}
	return []agents.Seed{{Source: filepath.Join(s.Home, ".claude.json"), Dest: filepath.Join(private, ".claude.json"), Keys: seeded}}
}

// Start writes the session's settings, points Claude at the profile's own
// configuration directory, and copies this project's history in, so a
// session can resume what you started outside the jail.
func (Adapter) Start(s agents.Session, argv []string) ([]string, map[string]string, error) {
	configDir := filepath.Join(s.Home, ".claude")
	if private := s.HostPath(configDir); private != "" {
		project := ProjectDir(s.Cwd)
		if err := copyProjectIn(filepath.Join(configDir, "projects", project), filepath.Join(private, "projects", project)); err != nil {
			return nil, nil, fmt.Errorf("copy the Claude project directory: %w", err)
		}
	}
	data, err := Settings(s.Profile, s.Cwd, osFiles{})
	if err != nil {
		return nil, nil, err
	}
	path, err := s.WriteFile("claude-settings.json", data)
	if err != nil {
		return nil, nil, err
	}
	args := Args(argv, path)
	if s.MCPConfig != "" {
		args = append(args[:1], append([]string{"--mcp-config", s.MCPConfig}, args[1:]...)...)
	}
	env := map[string]string{"CLAUDE_CONFIG_DIR": configDir}
	if s.Titled {
		env["CLAUDE_CODE_DISABLE_TERMINAL_TITLE"] = "1"
	}
	return args, env, nil
}

// End copies this project's transcripts back, so you can resume a jailed
// session outside the jail. Memory files the agent wrote stay behind.
func (Adapter) End(s agents.Session) error {
	configDir := filepath.Join(s.Home, ".claude")
	private := s.HostPath(configDir)
	if private == "" {
		return nil
	}
	project := ProjectDir(s.Cwd)
	return copyTranscriptsBack(filepath.Join(private, "projects", project), filepath.Join(configDir, "projects", project))
}

type osFiles struct{}

func (osFiles) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// Args adds doriath's settings file and drops the project and local settings
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
	timeout := int((p.Agent.ApprovalTimeout + hookTimeoutMargin) / time.Second)
	s.Hooks["PermissionRequest"] = append(s.Hooks["PermissionRequest"], hookGroup{
		Matcher: "*",
		Hooks: []hookCommand{{
			Type:    "command",
			Command: fmt.Sprintf("%s __hook claude permission-request --timeout %s", jail.ExePath, p.Agent.ApprovalTimeout),
			Timeout: timeout,
		}},
	})
	s.Hooks["SessionStart"] = append(s.Hooks["SessionStart"], hookGroup{
		Hooks: []hookCommand{{Type: "command", Command: jail.ExePath + " __hook claude session-start", Timeout: 10}},
	})
	if p.Agent.StatusLine {
		s.StatusLine = &statusLine{Type: "command", Command: jail.ExePath + " __statusline"}
	}
	s.Hooks["Notification"] = append(s.Hooks["Notification"], hookGroup{
		Hooks: []hookCommand{{Type: "command", Command: jail.ExePath + " __hook claude notification", Timeout: 10}},
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

// SessionStart is the hook output that adds context for the agent.
func SessionStart(context string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"hookSpecificOutput": map[string]string{
			"hookEventName":     "SessionStart",
			"additionalContext": context,
		},
	})
}
