package session

import (
	"fmt"
	"io"
	"time"

	"github.com/fnune/doriath/internal/approval"
)

type timings struct {
	w     io.Writer
	clock approval.Clock
	last  time.Time
}

func newTimings(w io.Writer, clock approval.Clock) *timings {
	t := &timings{w: w, clock: clock}
	if w != nil {
		t.last = clock.Now()
	}
	return t
}

func (t *timings) step(name string) {
	if t == nil || t.w == nil {
		return
	}
	now := t.clock.Now()
	fmt.Fprintf(t.w, "doriath: %6dms %s\n", now.Sub(t.last).Milliseconds(), name)
	t.last = now
}
