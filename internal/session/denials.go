package session

import (
	"sort"
	"sync"

	"github.com/fnune/doriath/internal/proxy"
)

type egressLog struct {
	next        proxy.Recorder
	firstDenial func(proxy.Event)

	mu     sync.Mutex
	denied map[denialKey]int
}

type denialKey struct {
	Host   string
	Reason string
}

type Denial struct {
	Host   string `json:"host"`
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

func newEgressLog(next proxy.Recorder) *egressLog {
	return &egressLog{next: next, denied: map[denialKey]int{}}
}

func (l *egressLog) Egress(e proxy.Event) {
	if e.Kind != "denied" {
		l.next.Egress(e)
		return
	}
	key := denialKey{Host: e.Host, Reason: e.Reason}
	l.mu.Lock()
	l.denied[key]++
	first := l.denied[key] == 1
	l.mu.Unlock()
	if first {
		l.next.Egress(e)
		if l.firstDenial != nil {
			l.firstDenial(e)
		}
	}
}

func (l *egressLog) Block(what, reason string) {
	l.mu.Lock()
	l.denied[denialKey{Host: what, Reason: reason}]++
	l.mu.Unlock()
}

// Denials returns every denied host and reason with its count, most frequent
// first.
func (l *egressLog) Denials() []Denial {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Denial, 0, len(l.denied))
	for k, n := range l.denied {
		out = append(out, Denial{Host: k.Host, Reason: k.Reason, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Host < out[j].Host
	})
	return out
}
