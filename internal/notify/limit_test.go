package notify

import (
	"errors"
	"testing"
	"time"
)

type stepClock struct{ now time.Time }

func (c *stepClock) Now() time.Time { return c.now }

type countingInformer struct{ sent int }

func (c *countingInformer) Inform(string, string, string) error { c.sent++; return nil }

func TestEveryInformPassesThroughTheRateLimit(t *testing.T) {
	clock := &stepClock{now: time.Unix(1000, 0)}
	next := &countingInformer{}
	l := Limit(next, clock)
	for range InformBurst {
		if err := l.Inform("s1", "doriath moved .envrc", "x"); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Inform("s1", "doriath moved .envrc", "x"); !errors.Is(err, ErrTooMany) {
		t.Fatalf("the eleventh notification: %v", err)
	}
	clock.now = clock.now.Add(InformRefillEvery)
	if err := l.Inform("s1", "t", "b"); err != nil {
		t.Errorf("after a minute: %v", err)
	}
	if err := l.Inform("s1", "t", "b"); !errors.Is(err, ErrTooMany) {
		t.Errorf("a second notification in the same minute: %v", err)
	}
	if next.sent != InformBurst+1 {
		t.Errorf("sent %d", next.sent)
	}
}
