package claude

import (
	"encoding/json"
	"fmt"
	"strings"
)

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

// Describe turns a tool call into a one-line summary and readable details.
func (r PermissionRequest) Describe() (summary, details string) {
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
		if d := str("description"); d != "" {
			summary = "Run: " + d
		}
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
	if len(details) > maxDetails {
		details = details[:maxDetails] + "…"
	}
	return summary, details
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

func ParseNotification(data []byte) (Notification, error) {
	var n Notification
	if err := json.Unmarshal(data, &n); err != nil {
		return Notification{}, fmt.Errorf("parse Notification input: %w", err)
	}
	return n, nil
}
