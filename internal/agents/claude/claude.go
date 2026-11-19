package claude

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/fnune/doriath/internal/agents"
	"github.com/fnune/doriath/internal/jail"
	"github.com/fnune/doriath/internal/profile"
)

// CredentialsFile is where Claude Code keeps its own login, with a refresh
// token, in its config directory. doriath holds the login instead, so a file
// there is a login on disk that the agent can read.
const CredentialsFile = ".credentials.json"

type Adapter struct{}

func (Adapter) Name() string { return "claude" }

func (Adapter) Command() string { return "claude" }

func (Adapter) Matches(argv []string) bool {
	return len(argv) > 0 && filepath.Base(argv[0]) == "claude"
}

var seeded = []string{
	"hasCompletedOnboarding", "lastOnboardingVersion", "lastReleaseNotesSeen", "claudeInChromeDefaultEnabled", "cachedChromeExtensionInstalled",
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

func (Adapter) Start(s agents.Session, argv []string) ([]string, map[string]string, error) {
	configDir := filepath.Join(s.Home, ".claude")
	if private := s.HostPath(configDir); private != "" {
		if err := os.Remove(filepath.Join(private, CredentialsFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("delete the login that Claude left on disk: %w", err)
		}
		if err := copyPluginsIn(filepath.Join(configDir, "plugins"), filepath.Join(private, "plugins")); err != nil {
			return nil, nil, fmt.Errorf("copy the Claude plugins: %w", err)
		}
		project := ProjectDir(s.Cwd)
		if err := copyProjectIn(filepath.Join(configDir, "projects", project), private, filepath.Join("projects", project)); err != nil {
			return nil, nil, fmt.Errorf("copy the Claude project directory: %w", err)
		}
	}
	data, err := Settings(s.Profile, s.Cwd, s.ToolWait, osFiles{})
	if err != nil {
		return nil, nil, err
	}
	path, err := s.WriteFile("claude-settings.json", data)
	if err != nil {
		return nil, nil, err
	}
	if err := placeUserSettings(s, configDir); err != nil {
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

func (Adapter) End(s agents.Session) error {
	configDir := filepath.Join(s.Home, ".claude")
	private := s.HostPath(configDir)
	if private == "" {
		return nil
	}
	project := ProjectDir(s.Cwd)
	return copyTranscriptsBack(private, filepath.Join("projects", project), filepath.Join(configDir, "projects", project))
}

func placeUserSettings(s agents.Session, configDir string) error {
	own := filepath.Join(configDir, "settings.json")
	data, err := os.ReadFile(own)
	if errors.Is(err, fs.ErrNotExist) {
		data = []byte("{}\n")
	} else if err != nil {
		return fmt.Errorf("read your Claude settings: %w", err)
	}
	return s.Place(own, data)
}

var settingsTouches = []time.Duration{0, time.Second, 3 * time.Second, 10 * time.Second}

func (Adapter) Started(s agents.Session) error {
	settings := filepath.Join(s.Home, ".claude", "settings.json")
	for _, after := range settingsTouches {
		s.Later(after, func() error { return s.Touch(settings) })
	}
	return nil
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
	DeniedMcpServers          []mcpServerRef    `json:"deniedMcpServers,omitempty"`
	AllowedMcpServers         []mcpServerRef    `json:"allowedMcpServers,omitempty"`
	Permissions               permissions       `json:"permissions"`
	Hooks                     map[string][]any  `json:"hooks"`
	Env                       map[string]string `json:"env,omitempty"`
}

type mcpServerRef struct {
	ServerName string `json:"serverName,omitempty"`
	ServerURL  string `json:"serverUrl,omitempty"`
}

func serverRef(nameOrURL string) mcpServerRef {
	if strings.Contains(nameOrURL, "://") {
		return mcpServerRef{ServerURL: nameOrURL}
	}
	return mcpServerRef{ServerName: nameOrURL}
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
func Settings(p *profile.Profile, cwd string, toolWait time.Duration, files Files) ([]byte, error) {
	s := settings{
		DisableClaudeAiConnectors: p.Claude.DisableConnectors,
		Permissions:               permissions{Ask: slices.Clone(p.Claude.Ask), Deny: slices.Clone(p.Claude.Deny)},
		Hooks:                     map[string][]any{},
	}
	for _, name := range p.Claude.DeniedMCPServers {
		s.DeniedMcpServers = append(s.DeniedMcpServers, serverRef(name))
	}
	if len(p.Claude.AllowedMCPServers) > 0 {
		for _, m := range p.MCP {
			s.AllowedMcpServers = append(s.AllowedMcpServers, mcpServerRef{ServerName: m.Name})
		}
		for _, name := range p.Claude.AllowedMCPServers {
			s.AllowedMcpServers = append(s.AllowedMcpServers, serverRef(name))
		}
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
	timeout := int((toolWait + hookTimeoutMargin) / time.Second)
	s.Hooks["PermissionRequest"] = append(s.Hooks["PermissionRequest"], hookGroup{
		Matcher: "*",
		Hooks: []hookCommand{{
			Type:    "command",
			Command: fmt.Sprintf("%s __hook claude permission-request --timeout %s", jail.ExePath, toolWait),
			Timeout: timeout,
		}},
	})
	s.Hooks["SessionStart"] = append(s.Hooks["SessionStart"], hookGroup{
		Hooks: []hookCommand{{Type: "command", Command: jail.ExePath + " __hook claude session-start", Timeout: 10}},
	})
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
	if len(bytes.TrimSpace(data)) == 0 {
		return projectSettings{}, nil
	}
	var ps projectSettings
	if err := json.Unmarshal(data, &ps); err != nil {
		return projectSettings{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return ps, nil
}

func ProjectDir(cwd string) string {
	return nonAlnum.ReplaceAllString(cwd, "-")
}

var nonAlnum = regexp.MustCompile(`[^A-Za-z0-9]`)
