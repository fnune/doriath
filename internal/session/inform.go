package session

import (
	"sync"
	"time"
)

const (
	informBurst = 10
	refillEvery = time.Minute
)

type rateLimit struct {
	burst    float64
	mu       sync.Mutex
	tokens   float64
	last     time.Time
	dropping bool
}

func newRateLimit(burst float64) *rateLimit {
	return &rateLimit{burst: burst}
}

func (l *rateLimit) allow(now time.Time) (ok, firstDropped bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last.IsZero() {
		l.tokens = l.burst
	} else {
		l.tokens = min(l.burst, l.tokens+float64(now.Sub(l.last))/float64(refillEvery))
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
