package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fnune/girdle/internal/approval"
	"github.com/fnune/girdle/internal/session"
)

const bashRequest = `{
  "session_id": "abc123",
  "transcript_path": "/home/u/.claude/projects/x/abc123.jsonl",
  "cwd": "/home/u/app",
  "permission_mode": "default",
  "hook_event_name": "PermissionRequest",
  "tool_name": "Bash",
  "tool_input": {"command": "rm -rf build", "description": "Remove the build directory"}
}`

type hookOutput struct {
	HookSpecificOutput struct {
		HookEventName     string `json:"hookEventName"`
		AdditionalContext string `json:"additionalContext"`
		Decision          struct {
			Behavior string `json:"behavior"`
			Message  string `json:"message"`
		} `json:"decision"`
	} `json:"hookSpecificOutput"`
}

func decodeHook(t *testing.T, out string) hookOutput {
	t.Helper()
	var h hookOutput
	if err := json.Unmarshal([]byte(out), &h); err != nil {
		t.Fatalf("hook output %q: %v", out, err)
	}
	return h
}

func TestHookPermissionRequestAllow(t *testing.T) {
	b := startBroker(t)
	b.set(approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingOnce}, nil)
	out, err := hook(t, "permission-request", bashRequest, "--timeout", "45s")
	if err != nil {
		t.Fatal(err)
	}
	got := b.lastSubmit(t)
	want := session.SubmitParams{
		Agent:          "claude",
		Summary:        "Run: Remove the build directory",
		Details:        "rm -rf build",
		Scope:          "tool Bash rm -rf build",
		TimeoutSeconds: 45,
	}
	if got != want {
		t.Errorf("submitted %+v, want %+v", got, want)
	}
	h := decodeHook(t, out)
	if h.HookSpecificOutput.HookEventName != "PermissionRequest" || h.HookSpecificOutput.Decision.Behavior != "allow" || h.HookSpecificOutput.Decision.Message != "" {
		t.Errorf("allow = %s", out)
	}
}

func TestHookPermissionRequestDeny(t *testing.T) {
	b := startBroker(t)
	b.set(approval.Decision{Verdict: approval.VerdictDeny, Reason: "use make clean"}, nil)
	out, err := hook(t, "permission-request", `{"tool_name":"mcp__github__create_issue","tool_input":{"title":"x"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.lastSubmit(t); got.Scope != "tool mcp__github__create_issue" || got.Summary != "Use github: create_issue" || got.TimeoutSeconds != 60 {
		t.Errorf("submitted %+v", got)
	}
	h := decodeHook(t, out)
	if h.HookSpecificOutput.Decision.Behavior != "deny" || h.HookSpecificOutput.Decision.Message != "Denied by the user through girdle. Reason: use make clean" {
		t.Errorf("deny = %s", out)
	}

	b.set(approval.Decision{Verdict: approval.VerdictDeny}, nil)
	out, err = hook(t, "permission-request", bashRequest)
	if err != nil {
		t.Fatal(err)
	}
	if h := decodeHook(t, out); h.HookSpecificOutput.Decision.Message != "Denied by the user through girdle." {
		t.Errorf("deny without a reason = %s", out)
	}
}

func TestHookPermissionRequestFallsBackToClaude(t *testing.T) {
	b := startBroker(t)
	b.set(approval.Decision{Verdict: approval.VerdictNone}, nil)
	if out, err := hook(t, "permission-request", bashRequest); err != nil || out != "" {
		t.Errorf("no decision = %q, %v; want no output so Claude shows its own prompt", out, err)
	}

	b.set(approval.Decision{}, errors.New("session ending"))
	if out, err := hook(t, "permission-request", bashRequest); err != nil || out != "" {
		t.Errorf("broker error = %q, %v", out, err)
	}

	t.Setenv("GIRDLE_BROKER", filepath.Join(t.TempDir(), "gone.sock"))
	if out, err := hook(t, "permission-request", bashRequest); err != nil || out != "" {
		t.Errorf("unreachable broker = %q, %v", out, err)
	}
}

func TestHookRejectsBadInput(t *testing.T) {
	startBroker(t)
	if _, err := hook(t, "permission-request", `{"tool_input":{}}`); err == nil {
		t.Error("a request without tool_name must fail")
	}
	if _, err := hook(t, "permission-request", `not json`); err == nil {
		t.Error("input that is not JSON must fail")
	}
	if _, err := hook(t, "stop", `{}`); err == nil || !strings.Contains(err.Error(), "unknown event") {
		t.Errorf("unknown event = %v", err)
	}
	if err := cmdHook([]string{"codex", "notification"}, strings.NewReader(""), &strings.Builder{}); err == nil {
		t.Error("only claude has hooks")
	}
	t.Setenv("GIRDLE_BROKER", "")
	if _, err := hook(t, "notification", `{}`); err == nil || !strings.Contains(err.Error(), "GIRDLE_BROKER") {
		t.Errorf("outside a jail = %v", err)
	}
}

func TestHookNotification(t *testing.T) {
	b := startBroker(t)
	if out, err := hook(t, "notification", `{"session_id":"abc","hook_event_name":"Notification","message":"Claude needs your permission to use Bash","notification_type":"permission_prompt"}`); err != nil || out != "" {
		t.Fatalf("notification = %q, %v", out, err)
	}
	if out, err := hook(t, "notification", `{"message":"Done","title":"Task finished"}`); err != nil || out != "" {
		t.Fatalf("notification = %q, %v", out, err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	want := []session.InformParams{
		{Title: "Claude Code", Body: "Claude needs your permission to use Bash"},
		{Title: "Task finished", Body: "Done"},
	}
	if len(b.informs) != 2 || b.informs[0] != want[0] || b.informs[1] != want[1] {
		t.Errorf("informed %+v", b.informs)
	}
}

func TestHookSessionStart(t *testing.T) {
	b := startBroker(t)
	b.setStatus(session.Status{Session: "s1", Profile: "kitchen", Hosts: []string{"proxy.golang.org"}})
	out, err := hook(t, "session-start", `{"session_id":"abc","hook_event_name":"SessionStart","source":"startup"}`)
	if err != nil {
		t.Fatal(err)
	}
	h := decodeHook(t, out)
	ctx := h.HookSpecificOutput.AdditionalContext
	if h.HookSpecificOutput.HookEventName != "SessionStart" || !strings.Contains(ctx, `girdle profile "kitchen" (session s1)`) || !strings.Contains(ctx, "  - proxy.golang.org\n") {
		t.Errorf("session-start = %s", out)
	}
}
