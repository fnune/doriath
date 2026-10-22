package agents

import (
	"io"
	"time"

	"github.com/fnune/doriath/internal/approval"
)

// Hooks is an adapter whose agent runs doriath from its hooks, as
// doriath __hook NAME EVENT, with the event's input on stdin.
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

// Broker is the session, as a hook inside the jail reaches it.
type Broker interface {
	Describe() (string, error)
	// Ask waits for your answer to a tool call, or returns verdict none
	// when nobody answers in time.
	Ask(q Question) (approval.Decision, error)
	Inform(title, body string) error
}

type Question struct {
	Summary string
	Note    string
	Details string
	// Scope is what an allow for the session covers.
	Scope string
}

func DenialMessage(d approval.Decision) string {
	message := "Denied by the user through doriath."
	if d.Reason != "" {
		message += " Reason: " + d.Reason
	}
	return message
}
