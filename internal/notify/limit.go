package notify

import (
	"fmt"
	"sync"
	"time"
)

const (
	InformBurst       = 10
	InformRefillEvery = time.Minute
)

var ErrTooMany = fmt.Errorf("too many notifications: doriath shows %d at once and one more each %s", InformBurst, InformRefillEvery)

type Informer interface {
	Inform(session, title, body string) error
}

type Clock interface {
	Now() time.Time
}

type Limited struct {
	next  Informer
	clock Clock

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func Limit(next Informer, clock Clock) *Limited {
	return &Limited{next: next, clock: clock, tokens: InformBurst}
}

func (l *Limited) Inform(session, title, body string) error {
	if !l.take() {
		return ErrTooMany
	}
	return l.next.Inform(session, title, body)
}

func (l *Limited) take() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	if !l.last.IsZero() {
		l.tokens = min(InformBurst, l.tokens+float64(now.Sub(l.last))/float64(InformRefillEvery))
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
