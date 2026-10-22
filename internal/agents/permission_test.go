package agents

import (
	"strings"
	"testing"
)

func TestDescribe(t *testing.T) {
	r, err := ParsePermissionRequest([]byte(`{"tool_name":"Bash","tool_input":{"command":"gh release create v1","description":"Create release"}}`))
	if err != nil {
		t.Fatal(err)
	}
	s, n, d := r.Describe()
	if s != "Run a command" || n != "Create release" || d != "gh release create v1" {
		t.Errorf("got %q %q %q", s, n, d)
	}
	r, _ = ParsePermissionRequest([]byte(`{"tool_name":"mcp__claude_ai_Linear__save_issue","tool_input":{"title":"x"}}`))
	if s, _, _ := r.Describe(); s != "Use claude_ai_Linear: save_issue" {
		t.Errorf("mcp summary = %q", s)
	}
	if _, err := ParsePermissionRequest([]byte(`{}`)); err == nil {
		t.Error("missing tool_name must be an error")
	}
	long, _ := ParsePermissionRequest([]byte(`{"tool_name":"Bash","tool_input":{"command":"` + strings.Repeat("a", 5000) + `"}}`))
	if _, _, d := long.Describe(); len(d) > maxDetails+4 {
		t.Errorf("details not truncated: %d", len(d))
	}
}

func TestDescribeNamesWhatTheToolTouches(t *testing.T) {
	for input, want := range map[string]string{
		`{"tool_name":"Bash","tool_input":{"command":"ls"}}`:                     "Run a command",
		`{"tool_name":"Edit","tool_input":{"file_path":"/src/main.go"}}`:         "Edit /src/main.go",
		`{"tool_name":"Write","tool_input":{"file_path":"/src/new.go"}}`:         "Write /src/new.go",
		`{"tool_name":"WebFetch","tool_input":{"url":"https://example.com"}}`:    "Fetch https://example.com",
		`{"tool_name":"Task","tool_input":{"prompt":"x"}}`:                       "Use Task",
		`{"tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch"}}`: "Change files",
	} {
		r, err := ParsePermissionRequest([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		if s, _, _ := r.Describe(); s != want {
			t.Errorf("%s: summary %q, want %q", input, s, want)
		}
	}
}

func TestPermissionDecision(t *testing.T) {
	for allow, want := range map[bool]string{
		false: `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"answered in doriath"}}}`,
		true:  `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow","message":"answered in doriath"}}}`,
	} {
		out, err := PermissionDecision(allow, "answered in doriath")
		if err != nil || string(out) != want {
			t.Errorf("allow=%v: got %s, %v", allow, out, err)
		}
	}
}
