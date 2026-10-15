package session

import (
	"sync"
	"time"
)

const (
	informBurst = 10
	informEvery = time.Minute
)

type informLimit struct {
	mu       sync.Mutex
	tokens   float64
	last     time.Time
	dropping bool
}

func (l *informLimit) allow(now time.Time) (ok, firstDropped bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last.IsZero() {
		l.tokens = informBurst
	} else {
		l.tokens = min(informBurst, l.tokens+float64(now.Sub(l.last))/float64(informEvery))
	}
	l.last = now
	if l.tokens >= 1 {
		l.tokens--
		l.dropping = false
		return true, false
	}
	firstDropped = !l.dropping
	l.dropping = true
	return false, firstDropped
}
