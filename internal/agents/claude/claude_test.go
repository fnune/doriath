package claude

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fnune/girdle/internal/agents"
	"github.com/fnune/girdle/internal/jail"
	"github.com/fnune/girdle/internal/profile"
)

type mapFiles map[string]string

func (m mapFiles) ReadFile(p string) ([]byte, error) {
	if v, ok := m[p]; ok {
		return []byte(v), nil
	}
	return nil, fs.ErrNotExist
}

func TestArgs(t *testing.T) {
	got := Args([]string{"/nix/store/x/bin/claude", "-r"}, "/run/girdle/claude-settings.json")
	want := []string{"/nix/store/x/bin/claude", "--settings", "/run/girdle/claude-settings.json", "--setting-sources", "user", "-r"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
	if !(Adapter{}).Matches([]string{"claude"}) || (Adapter{}).Matches([]string{"codex"}) || (Adapter{}).Matches(nil) {
		t.Fatal("Matches")
	}
}

func TestSettings(t *testing.T) {
	p := &profile.Profile{Claude: profile.Claude{
		DisableConnectors: true,
		DeniedMCPServers:  []string{"claude.ai Gmail"},
		Ask:               []string{"mcp__claude-in-chrome__javascript_tool"},
		ApprovalTimeout:   60 * time.Second,
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
	if pr["command"] != jail.ExePath+" hook claude permission-request --timeout 1m0s" || pr["timeout"].(float64) != 90 {
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

func TestDescribe(t *testing.T) {
	r, err := ParsePermissionRequest([]byte(`{"tool_name":"Bash","tool_input":{"command":"gh release create v1","description":"Create release"}}`))
	if err != nil {
		t.Fatal(err)
	}
	s, d := r.Describe()
	if s != "Run: Create release" || d != "gh release create v1" {
		t.Errorf("got %q %q", s, d)
	}
	r, _ = ParsePermissionRequest([]byte(`{"tool_name":"mcp__claude_ai_Linear__save_issue","tool_input":{"title":"x"}}`))
	if s, _ := r.Describe(); s != "Use claude_ai_Linear: save_issue" {
		t.Errorf("mcp summary = %q", s)
	}
	if _, err := ParsePermissionRequest([]byte(`{}`)); err == nil {
		t.Error("missing tool_name must be an error")
	}
	long, _ := ParsePermissionRequest([]byte(`{"tool_name":"Bash","tool_input":{"command":"` + strings.Repeat("a", 5000) + `"}}`))
	if _, d := long.Describe(); len(d) > maxDetails+4 {
		t.Errorf("details not truncated: %d", len(d))
	}
}

func TestPermissionDecision(t *testing.T) {
	out, err := PermissionDecision(false, "denied by the user")
	if err != nil {
		t.Fatal(err)
	}
	want := `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"denied by the user"}}}`
	if string(out) != want {
		t.Fatalf("got %s", out)
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
		Profile: &profile.Profile{Claude: profile.Claude{ApprovalTimeout: time.Minute}},
		Home:    home,
		Cwd:     cwd,
		HostPath: func(p string) string {
			if p == filepath.Join(home, ".claude") {
				return private
			}
			return ""
		},
		WriteFile: func(name string, data []byte) (string, error) {
			return "/run/girdle/" + name, os.WriteFile(filepath.Join(jailDir, name), data, 0o644)
		},
	}
	argv, env, err := Adapter{}.Start(s, []string{"claude", "-p", "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if argv[1] != "--settings" || argv[2] != "/run/girdle/claude-settings.json" || env["CLAUDE_CONFIG_DIR"] != filepath.Join(home, ".claude") {
		t.Fatalf("argv %v, env %v", argv, env)
	}
	if _, err := os.Stat(filepath.Join(private, "projects", project, "earlier.jsonl")); err != nil {
		t.Fatal("earlier transcripts must be there to resume")
	}
	if _, err := os.Stat(filepath.Join(jailDir, "claude-settings.json")); err != nil {
		t.Fatal(err)
	}
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
