package agents

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fnune/doriath/internal/approval"
)

// PermissionRequest is the part of a PermissionRequest hook's input that
// doriath uses. Claude Code and Codex send the same shape.
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
	case r.ToolName == "apply_patch":
		summary = "Change files"
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
// request. Without a decision the hook prints nothing, and the agent shows
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

// AnswerPermission puts a PermissionRequest hook's tool call in doriath's
// queue. Without an answer it prints nothing, and the agent shows its own
// prompt. leftToAgent names the tools that are themselves questions to you.
func AnswerPermission(call HookCall, agent string, leftToAgent func(tool string) bool) ([]byte, error) {
	req, err := ParsePermissionRequest(call.Input)
	if err != nil {
		return nil, err
	}
	if leftToAgent != nil && leftToAgent(req.ToolName) {
		return nil, nil
	}
	summary, note, details := req.Describe()
	scope := "tool " + req.ToolName
	if req.ToolName == "Bash" {
		scope += " " + details
	}
	d, err := call.Broker.Ask(Question{Summary: summary, Note: note, Details: details, Scope: scope})
	if err != nil {
		fmt.Fprintf(call.Stderr, "doriath: no decision, falling back to %s's prompt: %v\n", agent, err)
		return nil, nil
	}
	switch d.Verdict {
	case approval.VerdictAllow:
		return PermissionDecision(true, "")
	case approval.VerdictDeny:
		return PermissionDecision(false, DenialMessage(d))
	}
	return nil, nil
}

// SessionStart is the hook output that adds context for the agent.
func SessionStart(context string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"hookSpecificOutput": map[string]string{
			"hookEventName":     "SessionStart",
			"additionalContext": context,
		},
	})
}
