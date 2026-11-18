package session

import (
	"bytes"
	"testing"
	"time"
)

type steppingClock struct {
	stillClock
	now time.Time
}

func (c *steppingClock) Now() time.Time { return c.now }

func TestEachStepPrintsTheTimeSinceTheStepBefore(t *testing.T) {
	var out bytes.Buffer
	clock := &steppingClock{now: time.Unix(0, 0)}
	steps := newTimings(&out, clock)
	clock.now = clock.now.Add(40 * time.Millisecond)
	steps.step("find repositories")
	clock.now = clock.now.Add(5 * time.Millisecond)
	steps.step("fetch secrets")
	want := "doriath:     40ms find repositories\ndoriath:      5ms fetch secrets\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestASessionPrintsNoTimingsUnlessAsked(t *testing.T) {
	newTimings(nil, nil).step("fetch secrets")
	var unset *timings
	unset.step("fetch secrets")
}
