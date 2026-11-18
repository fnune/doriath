package agents

import (
	"encoding/json"
	"io"
	"time"

	"github.com/fnune/doriath/internal/approval"
)

type Hooks interface {
	Hook(call HookCall) ([]byte, error)
}

type HookCall struct {
	Event   string
	Input   []byte
	Timeout time.Duration
	Broker  Broker
	Stderr  io.Writer
}

type Broker interface {
	Started() error
	Describe() (string, error)
	// Ask waits for your answer to a tool call, or returns verdict none
	// when nobody answers in time.
	Ask(q Question) (approval.Decision, error)
	Inform(title, body string) error
}

// Question is a tool call as the agent sent it. The session describes it
// and scopes it, so that a process in the jail cannot choose what an allow
// covers.
type Question struct {
	Tool  string
	Input json.RawMessage
}

func DenialMessage(d approval.Decision) string {
	message := "Denied by the user through doriath."
	if d.Reason != "" {
		message += " Reason: " + d.Reason
	}
	return message
}
