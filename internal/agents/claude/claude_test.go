package claude

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/agents"
	"github.com/fnune/doriath/internal/jail"
	"github.com/fnune/doriath/internal/profile"
)

type mapFiles map[string]string

func (m mapFiles) ReadFile(p string) ([]byte, error) {
	if v, ok := m[p]; ok {
		return []byte(v), nil
	}
	return nil, fs.ErrNotExist
}

func TestArgs(t *testing.T) {
	got := Args([]string{"/nix/store/x/bin/claude", "-r"}, "/run/doriath/claude-settings.json")
	want := []string{"/nix/store/x/bin/claude", "--settings", "/run/doriath/claude-settings.json", "--setting-sources", "user", "-r"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
	if !(Adapter{}).Matches([]string{"claude"}) || (Adapter{}).Matches([]string{"codex"}) || (Adapter{}).Matches(nil) {
		t.Fatal("Matches")
	}
}

func TestSettings(t *testing.T) {
	p := &profile.Profile{Agent: profile.Agent{ApprovalTimeout: 60 * time.Second}, Claude: profile.Claude{
		DisableConnectors: true,
		DeniedMCPServers:  []string{"claude.ai Gmail"},
		Ask:               []string{"mcp__claude-in-chrome__javascript_tool"},
	}}
	files := mapFiles{
		"/w/.claude/settings.json":       `{"permissions":{"allow":["Bash(just check)"],"deny":["Bash(rm -rf:*)"]},"hooks":{"PostToolUse":[{"matcher":"Edit","hooks":[{"type":"command","command":"just fmt"}]}]}}`,
		"/w/.claude/settings.local.json": `{"permissions":{"allow":["Bash(go test:*)"]},"env":{"FOO":"1"}}`,
	}
	data, err := Settings(p, "/w", files)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got["disableClaudeAiConnectors"] != true {
		t.Error("connectors not disabled")
	}
	perms := got["permissions"].(map[string]any)
	if len(perms["allow"].([]any)) != 2 || len(perms["deny"].([]any)) != 1 || perms["ask"].([]any)[0] != "mcp__claude-in-chrome__javascript_tool" {
		t.Errorf("permissions = %v", perms)
	}
	hooks := got["hooks"].(map[string]any)
	pr := hooks["PermissionRequest"].([]any)[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	if pr["command"] != jail.ExePath+" __hook claude permission-request --timeout 1m0s" || pr["timeout"].(float64) != 90 {
		t.Errorf("permission hook = %v", pr)
	}
	if _, ok := hooks["PostToolUse"]; !ok {
		t.Error("project hooks must be kept")
	}
	if got["env"].(map[string]any)["FOO"] != "1" {
		t.Error("project env must be kept")
	}

	if _, err := Settings(p, "/w", mapFiles{"/w/.claude/settings.json": "{"}); err == nil {
		t.Error("broken project settings must be an error")
	}
}

func TestProjectDir(t *testing.T) {
	for in, want := range map[string]string{
		"/home/u/.home.nix":                         "-home-u--home-nix",
		"/home/u/Development/acme/acme-service": "-home-u-Development-acme-acme-service",
	} {
		if got := ProjectDir(in); got != want {
			t.Errorf("ProjectDir(%q) = %q", in, got)
		}
	}
}

func TestStartAndEnd(t *testing.T) {
	root := t.TempDir()
	home, private, jailDir := filepath.Join(root, "home"), filepath.Join(root, "cache", "claude"), filepath.Join(root, "jail")
	for _, d := range []string{home, private, jailDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cwd := filepath.Join(home, "app")
	project := ProjectDir(cwd)
	earlier := filepath.Join(home, ".claude", "projects", project, "earlier.jsonl")
	if err := os.MkdirAll(filepath.Dir(earlier), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(earlier, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := agents.Session{
		Profile: &profile.Profile{Agent: profile.Agent{ApprovalTimeout: time.Minute}},
		Home:    home,
		Cwd:     cwd,
		HostPath: func(p string) string {
			if p == filepath.Join(home, ".claude") {
				return private
			}
			return ""
		},
		WriteFile: func(name string, data []byte) (string, error) {
			return "/run/doriath/" + name, os.WriteFile(filepath.Join(jailDir, name), data, 0o644)
		},
	}
	argv, env, err := Adapter{}.Start(s, []string{"claude", "-p", "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if argv[1] != "--settings" || argv[2] != "/run/doriath/claude-settings.json" || env["CLAUDE_CONFIG_DIR"] != filepath.Join(home, ".claude") {
		t.Fatalf("argv %v, env %v", argv, env)
	}
	if _, ok := env["CLAUDE_CODE_DISABLE_TERMINAL_TITLE"]; ok {
		t.Error("Claude may keep the title when doriath does not set it")
	}
	s.Titled = true
	if _, env, err = (Adapter{}).Start(s, []string{"claude"}); err != nil || env["CLAUDE_CODE_DISABLE_TERMINAL_TITLE"] != "1" {
		t.Errorf("titled session env %v, %v", env, err)
	}
	if _, err := os.Stat(filepath.Join(private, "projects", project, "earlier.jsonl")); err != nil {
		t.Fatal("earlier transcripts must be there to resume")
	}
	if _, err := os.Stat(filepath.Join(jailDir, "claude-settings.json")); err != nil {
		t.Fatal(err)
	}
	s.MCPConfig = "/run/doriath/mcp.json"
	withMCP, _, err := Adapter{}.Start(s, []string{"claude"})
	if err != nil || withMCP[1] != "--mcp-config" || withMCP[2] != "/run/doriath/mcp.json" {
		t.Fatalf("argv %v, %v", withMCP, err)
	}
	s.MCPConfig = ""
	if err := os.WriteFile(filepath.Join(private, "projects", project, "new.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (Adapter{}).End(s); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "projects", project, "new.jsonl")); err != nil {
		t.Fatal("the session's transcript must come back")
	}
}
