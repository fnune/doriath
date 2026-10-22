package claude

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/fnune/doriath/internal/agents"
)

func (Adapter) Hook(call agents.HookCall) ([]byte, error) {
	switch call.Event {
	case "session-start":
		text, err := call.Broker.Describe()
		if err != nil {
			return nil, err
		}
		return agents.SessionStart(text)
	case "permission-request":
		return agents.AnswerPermission(call, "Claude", asksYou)
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

var questionTools = []string{"AskUserQuestion", "ExitPlanMode"}

func asksYou(tool string) bool { return slices.Contains(questionTools, tool) }

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
