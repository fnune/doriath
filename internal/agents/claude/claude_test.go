package claude

import (
	"encoding/json"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"

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
	if !Matches([]string{"claude"}) || Matches([]string{"codex"}) || Matches(nil) {
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

type fakeHost map[string]string

func (h fakeHost) Kind(p string) string { return h[p] }

func (h fakeHost) Resolve(p string) (string, error) {
	if p == "/home/u/.claude/settings.json" {
		return "/nix/store/x-home-manager-files/.claude/settings.json", nil
	}
	return p, nil
}

func TestStateBinds(t *testing.T) {
	st := State{Home: "/home/u", Cwd: "/home/u/k", Private: "/c/claude/home", ConfigCopy: "/c/claude.json", ShareLogin: true}
	host := fakeHost{
		"/home/u/.claude/.credentials.json": "file",
		"/home/u/.claude/settings.json":     "other",
		"/home/u/.claude/plugins":           "dir",
		"/home/u/.claude/history.jsonl":     "file",
	}
	binds := st.Binds(host)
	find := func(dest string) (jail.Bind, bool) {
		i := slices.IndexFunc(binds, func(b jail.Bind) bool { return b.Dest == dest })
		if i < 0 {
			return jail.Bind{}, false
		}
		return binds[i], true
	}
	if b, ok := find("/home/u/.claude"); !ok || b.Source != "/c/claude/home" || b.ReadOnly {
		t.Errorf("~/.claude must be the profile's own writable directory: %+v", b)
	}
	if b, ok := find("/home/u/.claude/settings.json"); !ok || !b.ReadOnly || b.Source != "/nix/store/x-home-manager-files/.claude/settings.json" {
		t.Errorf("settings must be the resolved file, read-only: %+v", b)
	}
	if b, ok := find("/home/u/.claude/plugins"); !ok || !b.ReadOnly {
		t.Error("plugins must be read-only")
	}
	if b, ok := find("/home/u/.claude/.credentials.json"); !ok || b.ReadOnly {
		t.Error("credentials must be shared and writable")
	}
	if _, ok := find("/home/u/.claude/projects/-home-u-k"); !ok {
		t.Error("the session's own project must be visible")
	}
	if _, ok := find("/home/u/.claude/history.jsonl"); ok {
		t.Error("history must stay private to the profile")
	}
	if b, ok := find("/home/u/.claude.json"); !ok || b.Source != "/c/claude.json" {
		t.Error("~/.claude.json must be a copy")
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

func TestFilterMCPServers(t *testing.T) {
	in := []byte(`{"numStartups":3,"mcpServers":{"notion":{"type":"http"},"bazel":{"command":"bazel-mcp"}},"projects":{"/w":{"mcpServers":{"notion":{}},"allowedTools":[]}}}`)
	out, err := FilterMCPServers(in, []string{"bazel"})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		NumStartups int                        `json:"numStartups"`
		MCPServers  map[string]json.RawMessage `json:"mcpServers"`
		Projects    map[string]struct {
			MCPServers   map[string]json.RawMessage `json:"mcpServers"`
			AllowedTools []string                   `json:"allowedTools"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got.NumStartups != 3 || len(got.MCPServers) != 1 || got.MCPServers["bazel"] == nil || len(got.Projects["/w"].MCPServers) != 0 || got.Projects["/w"].AllowedTools == nil {
		t.Fatalf("got %s", out)
	}
	same, _ := FilterMCPServers(in, nil)
	if string(same) != string(in) {
		t.Fatal("a nil list must keep the document as is")
	}
}

func TestLoginIsPrivateByDefault(t *testing.T) {
	st := State{Home: "/home/u", Cwd: "/home/u/k", Private: "/c/claude/home"}
	for _, b := range st.Binds(fakeHost{"/home/u/.claude/.credentials.json": "file"}) {
		if b.Dest == "/home/u/.claude/.credentials.json" {
			t.Fatal("the desktop login must not be in the jail unless the profile shares it")
		}
	}
}
