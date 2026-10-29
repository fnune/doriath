package session

import (
	"testing"
	"time"
)

func TestInformIsRateLimited(t *testing.T) {
	l := newRateLimit(informBurst)
	now := time.Unix(1000, 0)
	for i := range informBurst {
		if ok, _ := l.allow(now); !ok {
			t.Fatalf("notification %d of the burst was dropped", i)
		}
	}
	if ok, first := l.allow(now); ok || !first {
		t.Fatalf("past the burst: ok %v, first dropped %v", ok, first)
	}
	if _, first := l.allow(now); first {
		t.Error("only the first drop is reported")
	}
	if ok, _ := l.allow(now.Add(refillEvery)); !ok {
		t.Error("a notification must pass once the limit refills")
	}
}
