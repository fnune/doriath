// Package codex adapts OpenAI's Codex CLI to doriath. The codex module gives
// it a private ~/.codex; this adapter writes its config.toml and hooks.json
// for the session, read-only, so the agent cannot add a hook that answers
// its own permission prompts, and those prompts go to doriath's approvals.
package codex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/fnune/doriath/internal/agents"
	"github.com/fnune/doriath/internal/jail"
	"github.com/fnune/doriath/internal/profile"
)

type Adapter struct{}

func (Adapter) Name() string { return "codex" }

func (Adapter) Command() string { return "codex" }

func (Adapter) Matches(argv []string) bool {
	return len(argv) > 0 && filepath.Base(argv[0]) == "codex"
}

func (Adapter) Seeds(agents.Session) []agents.Seed { return nil }

func (Adapter) End(agents.Session) error { return nil }

var travels = []string{
	"model", "model_reasoning_effort", "model_reasoning_summary", "model_verbosity",
	"personality", "approval_policy", "approvals_reviewer", "features", "tui",
	"file_opener", "hide_agent_reasoning", "show_raw_agent_reasoning",
}

// Start writes the session's config. Codex trusts hooks only from a hash
// you confirm in /hooks, or from /etc/codex, which the jail cannot add to,
// so it starts with --dangerously-bypass-hook-trust. That is safe here
// because both files are read-only and the project's .codex layer is
// marked untrusted, which keeps it from loading.
func (Adapter) Start(s agents.Session, argv []string) ([]string, map[string]string, error) {
	home := filepath.Join(s.Home, ".codex")
	own, err := os.ReadFile(filepath.Join(home, "config.toml"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("read your Codex config: %w", err)
	}
	config, err := Config(own, s)
	if err != nil {
		return nil, nil, err
	}
	if err := s.Place(filepath.Join(home, "config.toml"), config); err != nil {
		return nil, nil, err
	}
	hooks, err := Hooks(s.Profile.Agent.ApprovalTimeout)
	if err != nil {
		return nil, nil, err
	}
	if err := s.Place(filepath.Join(home, "hooks.json"), hooks); err != nil {
		return nil, nil, err
	}
	args := append([]string{argv[0], "--dangerously-bypass-hook-trust"}, argv[1:]...)
	return args, nil, nil
}

// Config is the session's config.toml: the keys of yours that travel, then
// what doriath sets. Codex's own sandbox needs user namespaces, which the
// jail does not give, and the jail already confines it.
func Config(own []byte, s agents.Session) ([]byte, error) {
	var mine map[string]any
	if _, err := toml.Decode(string(own), &mine); err != nil {
		return nil, fmt.Errorf("parse your Codex config: %w", err)
	}
	out := map[string]any{}
	for _, k := range travels {
		if v, ok := mine[k]; ok {
			out[k] = v
		}
	}
	if _, ok := out["approval_policy"]; !ok {
		out["approval_policy"] = "on-request"
	}
	out["sandbox_mode"] = "danger-full-access"
	out["check_for_update_on_startup"] = false
	out["cli_auth_credentials_store"] = "file"
	out["mcp_oauth_credentials_store"] = "file"
	out["analytics"] = map[string]any{"enabled": false}
	out["feedback"] = map[string]any{"enabled": false}
	out["otel"] = map[string]any{"metrics_exporter": "none"}
	out["projects"] = map[string]any{s.Cwd: map[string]any{"trust_level": "untrusted"}}
	if s.Instructions != "" {
		out["developer_instructions"] = s.Instructions
	}
	if servers := mcpServers(s.Profile.MCP); len(servers) > 0 {
		out["mcp_servers"] = servers
	}
	var b bytes.Buffer
	if err := toml.NewEncoder(&b).Encode(out); err != nil {
		return nil, fmt.Errorf("encode the Codex config: %w", err)
	}
	return b.Bytes(), nil
}

func mcpServers(servers []profile.MCPServer) map[string]any {
	out := map[string]any{}
	for _, s := range servers {
		if s.URL != "" {
			out[s.Name] = map[string]any{"url": s.URL}
			continue
		}
		server := map[string]any{"command": s.Command[0], "args": s.Command[1:]}
		if len(s.Env) > 0 {
			server["env"] = s.Env
		}
		out[s.Name] = server
	}
	return out
}

var hookTimeoutMargin = 30 * time.Second

type hookHandler struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout"`
}

type hookGroup struct {
	Hooks []hookHandler `json:"hooks"`
}

func Hooks(timeout time.Duration) ([]byte, error) {
	out, err := json.MarshalIndent(map[string]map[string][]hookGroup{"hooks": {
		"PermissionRequest": {{Hooks: []hookHandler{{
			Type:    "command",
			Command: fmt.Sprintf("%s __hook codex permission-request --timeout %s", jail.ExePath, timeout),
			Timeout: int((timeout + hookTimeoutMargin) / time.Second),
		}}}},
	}}, "", "  ")
	return append(out, '\n'), err
}

func (Adapter) Hook(call agents.HookCall) ([]byte, error) {
	if call.Event == "permission-request" {
		return agents.AnswerPermission(call, "Codex", nil)
	}
	return nil, fmt.Errorf("hook: unknown event %q", call.Event)
}
