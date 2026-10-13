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
	"strings"
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
	DeniedMcpServers          []deniedServer    `json:"deniedMcpServers,omitempty"`
	Permissions               permissions       `json:"permissions"`
	Hooks                     map[string][]any  `json:"hooks"`
	Env                       map[string]string `json:"env,omitempty"`
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

// projectSettings is the part of a repo's settings files that girdle keeps.
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

// State describes how the jail sees Claude's state. Shared is the real
// ~/.claude, because login tokens must stay in sync with the desktop. Masks
// hide what belongs to other projects. Frozen paths are read-only because
// Claude outside the jail later runs or obeys what they contain.
type State struct {
	Home string
	Cwd  string
	// Private is a profile-owned directory for the masks.
	Private string
	// ConfigCopy is a copy of ~/.claude.json made at session start.
	ConfigCopy string
}

var masked = []string{
	"backups", "daemon", "debug", "file-history", "history.jsonl", "ide", "jobs",
	"paste-cache", "session-env", "sessions", "shell-snapshots", "todos",
}

var frozen = []string{
	"CLAUDE.md", "agents", "chrome", "commands", "hooks", "plugins", "settings.json",
	"settings.local.json", "skills",
}

// Host tells existing paths apart, so the jail only binds what exists.
type Host interface {
	Kind(path string) string
}

// MaskSource returns the profile-owned stand-in for a masked entry.
func (st State) MaskSource(name string) string { return filepath.Join(st.Private, name) }

func (st State) Binds(host Host) []jail.Bind {
	dir := filepath.Join(st.Home, ".claude")
	binds := []jail.Bind{{Source: dir, Dest: dir}}
	if st.ConfigCopy != "" {
		binds = append(binds, jail.Bind{Source: st.ConfigCopy, Dest: filepath.Join(st.Home, ".claude.json")})
	}
	binds = append(binds, jail.Bind{Source: st.MaskSource("projects"), Dest: filepath.Join(dir, "projects")})
	own := ProjectDir(st.Cwd)
	binds = append(binds, jail.Bind{Source: filepath.Join(dir, "projects", own), Dest: filepath.Join(dir, "projects", own)})
	for _, name := range masked {
		if host.Kind(filepath.Join(dir, name)) != "" {
			binds = append(binds, jail.Bind{Source: st.MaskSource(name), Dest: filepath.Join(dir, name)})
		}
	}
	for _, name := range frozen {
		if p := filepath.Join(dir, name); host.Kind(p) != "" {
			binds = append(binds, jail.Bind{Source: p, Dest: p, ReadOnly: true})
		}
	}
	return binds
}

// MaskIsFile reports whether a masked entry is a file rather than a
// directory, so the caller can create the right kind of stand-in.
func MaskIsFile(name string) bool { return strings.HasSuffix(name, ".jsonl") }

func Masked() []string { return slices.Clone(masked) }
