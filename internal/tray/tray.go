package tray

import (
	"context"
	"fmt"
	"time"
)

type State struct {
	Waiting int
}

func (s State) Text() string {
	switch s.Waiting {
	case 0:
		return "No requests waiting"
	case 1:
		return "1 request waiting"
	}
	return fmt.Sprintf("%d requests waiting", s.Waiting)
}

type Icon interface {
	Show(State) error
}

type Counter interface {
	Waiting(ctx context.Context) (int, error)
}

// Run shows the state at once and again after each tick that changes it,
// until ctx ends. A count that fails keeps the last state.
func Run(ctx context.Context, counter Counter, icon Icon, ticks <-chan time.Time) error {
	shown := false
	var last State
	for {
		if n, err := counter.Waiting(ctx); err == nil {
			if s := (State{Waiting: n}); !shown || s != last {
				if err := icon.Show(s); err != nil {
					return fmt.Errorf("show the tray icon: %w", err)
				}
				shown, last = true, s
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticks:
		}
	}
}
