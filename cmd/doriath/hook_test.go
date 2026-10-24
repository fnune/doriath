package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/session"
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
	if got.Agent != "claude" || got.Tool != "Bash" || got.TimeoutSeconds != 45 || !strings.Contains(string(got.Input), `"command":"rm -rf build"`) {
		t.Errorf("submitted %+v", got)
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
	if got := b.lastSubmit(t); got.Tool != "mcp__github__create_issue" || string(got.Input) != `{"title":"x"}` || got.TimeoutSeconds != 60 {
		t.Errorf("submitted %+v", got)
	}
	h := decodeHook(t, out)
	if h.HookSpecificOutput.Decision.Behavior != "deny" || h.HookSpecificOutput.Decision.Message != "Denied by the user through doriath. Reason: use make clean" {
		t.Errorf("deny = %s", out)
	}

	b.set(approval.Decision{Verdict: approval.VerdictDeny}, nil)
	out, err = hook(t, "permission-request", bashRequest)
	if err != nil {
		t.Fatal(err)
	}
	if h := decodeHook(t, out); h.HookSpecificOutput.Decision.Message != "Denied by the user through doriath." {
		t.Errorf("deny without a reason = %s", out)
	}
}

func TestHookAllowsReadsWithoutAsking(t *testing.T) {
	b := startBroker(t)
	for _, input := range []string{
		`{"tool_name":"Read","tool_input":{"file_path":"/home/u/notes/todo.md"}}`,
		`{"tool_name":"Grep","tool_input":{"pattern":"x","path":"/home/u/notes"}}`,
	} {
		out, err := hook(t, "permission-request", input)
		if err != nil {
			t.Fatal(err)
		}
		if h := decodeHook(t, out); h.HookSpecificOutput.Decision.Behavior != "allow" {
			t.Errorf("%s: %s", input, out)
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.submits) != 0 {
		t.Errorf("reads reached the queue: %+v", b.submits)
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

	t.Setenv("DORIATH_BROKER", filepath.Join(t.TempDir(), "gone.sock"))
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
	t.Setenv("DORIATH_BROKER", "")
	if _, err := hook(t, "notification", `{}`); err == nil || !strings.Contains(err.Error(), "DORIATH_BROKER") {
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
	if out, err := hook(t, "notification", `{"message":"Claude is waiting for your input","notification_type":"idle_prompt"}`); err != nil || out != "" {
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
	if h.HookSpecificOutput.HookEventName != "SessionStart" || !strings.Contains(ctx, `doriath profile "kitchen" (session s1)`) || !strings.Contains(ctx, "  - proxy.golang.org\n") {
		t.Errorf("session-start = %s", out)
	}
}

func TestAQuestionToYouIsLeftToClaude(t *testing.T) {
	b := startBroker(t)
	b.set(approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingOnce}, nil)
	for _, tool := range []string{"AskUserQuestion", "ExitPlanMode"} {
		out, err := hook(t, "permission-request", `{"tool_name":"`+tool+`","tool_input":{}}`, "--timeout", "45s")
		if err != nil || out != "" {
			t.Errorf("%s: out %q, err %v", tool, out, err)
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.submits) != 0 {
		t.Errorf("the hook asked you whether Claude may ask you: %+v", b.submits)
	}
}
