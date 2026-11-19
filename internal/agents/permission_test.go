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
	if _, _, d := long.Describe(); len(d) > maxDetails+40 || !strings.HasSuffix(d, "[3000 more bytes not shown]") {
		t.Errorf("details not truncated with a notice: %d %q", len(d), d[len(d)-40:])
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

func TestAnAllowForAToolCoversOnlyCallsWithTheSameArguments(t *testing.T) {
	scope := func(input string) string {
		r, err := ParsePermissionRequest([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		return r.Scope()
	}
	a := scope(`{"tool_name":"mcp__linear__save_issue","tool_input":{"title":"a","team":"x"}}`)
	same := scope(`{"tool_name":"mcp__linear__save_issue","tool_input":{ "title": "a", "team": "x" }}`)
	other := scope(`{"tool_name":"mcp__linear__save_issue","tool_input":{"title":"b","team":"x"}}`)
	if a != same {
		t.Errorf("the same call has two scopes: %q %q", a, same)
	}
	if a == other {
		t.Errorf("a call with other arguments shares the scope %q", a)
	}
}

func TestAnAllowForAFileOrPageToolCoversItsFileOrPageWhateverTheContent(t *testing.T) {
	scope := func(input string) string {
		r, err := ParsePermissionRequest([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		return r.Scope()
	}
	for _, c := range []struct{ tool, field, value, other string }{
		{"Write", "file_path", "/tmp/ok", "/home/me/.bashrc"},
		{"Edit", "file_path", "/tmp/ok", "/home/me/.bashrc"},
		{"WebFetch", "url", "https://a.example", "https://b.example"},
	} {
		call := func(value, content string) string {
			return scope(`{"tool_name":"` + c.tool + `","tool_input":{"` + c.field + `":"` + value + `","content":"` + content + `","prompt":"` + content + `"}}`)
		}
		if call(c.value, "one") != call(c.value, "two") {
			t.Errorf("%s: two calls on %s have two scopes", c.tool, c.value)
		}
		if call(c.value, "one") == call(c.other, "one") {
			t.Errorf("%s: a call on %s shares the scope of %s", c.tool, c.other, c.value)
		}
	}
}
