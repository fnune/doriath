package claude

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/fnune/doriath/internal/agents"
	"github.com/fnune/doriath/internal/approval"
)

func (Adapter) Hook(call agents.HookCall) ([]byte, error) {
	switch call.Event {
	case "session-start":
		text, err := call.Broker.Describe()
		if err != nil {
			return nil, err
		}
		return SessionStart(text)
	case "permission-request":
		return permissionRequest(call)
	case "notification":
		n, err := ParseNotification(call.Input)
		if err != nil {
			return nil, err
		}
		if n.Idle() {
			return nil, nil
		}
		title := n.Title
		if title == "" {
			title = "Claude Code"
		}
		return nil, call.Broker.Inform(title, n.Message)
	}
	return nil, fmt.Errorf("hook: unknown event %q", call.Event)
}

func permissionRequest(call agents.HookCall) ([]byte, error) {
	req, err := ParsePermissionRequest(call.Input)
	if err != nil {
		return nil, err
	}
	if req.AsksYou() {
		return nil, nil
	}
	summary, note, details := req.Describe()
	scope := "tool " + req.ToolName
	if req.ToolName == "Bash" {
		scope += " " + details
	}
	d, err := call.Broker.Ask(agents.Question{Summary: summary, Note: note, Details: details, Scope: scope})
	if err != nil {
		fmt.Fprintln(call.Stderr, "doriath: no decision, falling back to Claude's prompt:", err)
		return nil, nil
	}
	switch d.Verdict {
	case approval.VerdictAllow:
		return PermissionDecision(true, "")
	case approval.VerdictDeny:
		return PermissionDecision(false, agents.DenialMessage(d))
	}
	return nil, nil
}

// PermissionRequest is the part of Claude Code's PermissionRequest hook input
// that doriath uses.
type PermissionRequest struct {
	SessionID string          `json:"session_id"`
	Cwd       string          `json:"cwd"`
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

func ParsePermissionRequest(data []byte) (PermissionRequest, error) {
	var r PermissionRequest
	if err := json.Unmarshal(data, &r); err != nil {
		return PermissionRequest{}, fmt.Errorf("parse PermissionRequest input: %w", err)
	}
	if r.ToolName == "" {
		return PermissionRequest{}, fmt.Errorf("PermissionRequest input has no tool_name")
	}
	return r, nil
}

const maxDetails = 2000

var questionTools = []string{"AskUserQuestion", "ExitPlanMode"}

// AsksYou reports whether the tool is itself a question to you, such as
// a choice between options or a plan to approve: Claude's own prompt shows
// it, and an approval to ask it would only repeat it.
func (r PermissionRequest) AsksYou() bool { return slices.Contains(questionTools, r.ToolName) }

// Describe turns a tool call into a one-line summary, the agent's own
// description of it, and readable details.
func (r PermissionRequest) Describe() (summary, note, details string) {
	var input map[string]any
	_ = json.Unmarshal(r.ToolInput, &input)
	str := func(k string) string {
		if s, ok := input[k].(string); ok {
			return s
		}
		return ""
	}
	switch {
	case r.ToolName == "Bash":
		summary = "Run a command"
		note = str("description")
		details = str("command")
	case r.ToolName == "Write" || r.ToolName == "Edit" || r.ToolName == "MultiEdit":
		summary = r.ToolName + " " + str("file_path")
	case r.ToolName == "WebFetch":
		summary = "Fetch " + str("url")
	case strings.HasPrefix(r.ToolName, "mcp__"):
		summary = "Use " + strings.ReplaceAll(strings.TrimPrefix(r.ToolName, "mcp__"), "__", ": ")
	default:
		summary = "Use " + r.ToolName
	}
	if details == "" && len(r.ToolInput) > 0 {
		details = string(r.ToolInput)
	}
	return summary, truncate(note), truncate(details)
}

func truncate(s string) string {
	if len(s) > maxDetails {
		return s[:maxDetails] + "…"
	}
	return s
}

type hookOutput struct {
	HookSpecificOutput hookSpecific `json:"hookSpecificOutput"`
}

type hookSpecific struct {
	HookEventName string       `json:"hookEventName"`
	Decision      hookDecision `json:"decision"`
}

type hookDecision struct {
	Behavior string `json:"behavior"`
	Message  string `json:"message,omitempty"`
}

// PermissionDecision is the hook's output. Allow and deny decide the
// request. Without a decision the hook prints nothing, and Claude Code shows
// its own prompt.
func PermissionDecision(allow bool, message string) ([]byte, error) {
	behavior := "deny"
	if allow {
		behavior = "allow"
	}
	return json.Marshal(hookOutput{HookSpecificOutput: hookSpecific{
		HookEventName: "PermissionRequest",
		Decision:      hookDecision{Behavior: behavior, Message: message},
	}})
}

type Notification struct {
	Message          string `json:"message"`
	Title            string `json:"title"`
	NotificationType string `json:"notification_type"`
}

// Idle reports a notice that Claude waits for your next message, which
// Claude itself shows on no desktop by default.
func (n Notification) Idle() bool { return n.NotificationType == "idle_prompt" }

func ParseNotification(data []byte) (Notification, error) {
	var n Notification
	if err := json.Unmarshal(data, &n); err != nil {
		return Notification{}, fmt.Errorf("parse Notification input: %w", err)
	}
	return n, nil
}
