package approval

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

func holdSetup() *Manager {
	return NewManager(realClock{}, &fakeNotifier{}, &fakeRecorder{}, &seqIDs{})
}

func TestHoldKeepsTheRequestAfterTheWait(t *testing.T) {
	m := holdSetup()
	var mu sync.Mutex
	var later []Decision
	d, id := m.Hold(Request{Kind: KindHTTP, Scope: "host a.example"}, time.Hour, 20*time.Millisecond, func(d Decision) {
		mu.Lock()
		later = append(later, d)
		mu.Unlock()
	})
	if d.Verdict != VerdictNone || id == "" || len(m.Pending()) != 1 {
		t.Fatalf("after the wait: %+v %q, pending %d", d, id, len(m.Pending()))
	}
	waited := make(chan Decision, 1)
	go func() {
		d, _ := m.Wait(context.Background(), id)
		waited <- d
	}()
	if err := m.Decide(id, Decision{Verdict: VerdictAllow, Lasting: LastingSession}); err != nil {
		t.Fatal(err)
	}
	if d := <-waited; d.Verdict != VerdictAllow {
		t.Fatalf("Wait = %+v", d)
	}
	if d, err := m.Wait(context.Background(), id); err != nil || d.Verdict != VerdictAllow {
		t.Fatalf("Wait after the decision = %+v, %v", d, err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		mu.Lock()
		n := len(later)
		mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("decided did not run")
		}
		time.Sleep(time.Millisecond)
	}
	if d, id := m.Hold(Request{Kind: KindHTTP, Scope: "host a.example"}, time.Hour, time.Hour, nil); d.Verdict != VerdictAllow || id != "" {
		t.Fatalf("a session grant answers at once: %+v %q", d, id)
	}
}

func TestHoldJoinsAnIdenticalRequest(t *testing.T) {
	m := holdSetup()
	req := Request{Kind: KindHTTP, Scope: "host b.example"}
	_, first := m.Hold(req, time.Hour, time.Millisecond, nil)
	_, second := m.Hold(req, time.Hour, time.Millisecond, nil)
	if first != second || len(m.Pending()) != 1 {
		t.Fatalf("ids %q and %q, pending %d", first, second, len(m.Pending()))
	}
	got := make(chan Decision, 1)
	go func() {
		d, _ := m.Hold(req, time.Hour, time.Hour, nil)
		got <- d
	}()
	time.Sleep(10 * time.Millisecond)
	if err := m.Decide(first, Decision{Verdict: VerdictDeny}); err != nil {
		t.Fatal(err)
	}
	if d := <-got; d.Verdict != VerdictDeny {
		t.Fatalf("a held request sees the decision of the one it joined: %+v", d)
	}
}

func TestWaitForAnUnknownRequest(t *testing.T) {
	if _, err := holdSetup().Wait(context.Background(), "nope"); err == nil {
		t.Fatal("want an error")
	}
}

func TestWaitScopeAnswersWithTheNewestDecision(t *testing.T) {
	m, _, _, _ := setup()
	for _, verdict := range []Verdict{VerdictAllow, VerdictDeny} {
		got := submitAsync(m, "rule egress a.example")
		if err := m.Decide(waitPending(t, m).ID, Decision{Verdict: verdict, Lasting: LastingOnce}); err != nil {
			t.Fatal(err)
		}
		<-got
	}
	if d, err := m.WaitScope(context.Background(), "rule egress a.example"); err != nil || d.Verdict != VerdictDeny {
		t.Fatalf("WaitScope = %+v, %v", d, err)
	}
	if _, err := m.WaitScope(context.Background(), "rule egress b.example"); !errors.Is(err, ErrUnknownRequest) {
		t.Fatalf("a scope nobody asked about: %v", err)
	}
}

func TestWaitScopeWaitsForThePendingRequest(t *testing.T) {
	m, _, _, _ := setup()
	submitAsync(m, "path write /src")
	req := waitPending(t, m)
	waited := make(chan Decision, 1)
	go func() {
		d, _ := m.WaitScope(context.Background(), "path write /src")
		waited <- d
	}()
	if err := m.Decide(req.ID, Decision{Verdict: VerdictAllow, Lasting: LastingSession}); err != nil {
		t.Fatal(err)
	}
	if d := <-waited; d.Verdict != VerdictAllow {
		t.Fatalf("WaitScope = %+v", d)
	}
}

func TestWaitStopsWhenTheCallerGivesUp(t *testing.T) {
	m, _, _, _ := setup()
	submitAsync(m, "s")
	req := waitPending(t, m)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d, err := m.Wait(ctx, req.ID)
	if err != nil || d.Verdict != VerdictNone || d.Reason != "stopped waiting" {
		t.Fatalf("Wait = %+v, %v", d, err)
	}
	if len(m.Pending()) != 1 {
		t.Fatal("giving up on a wait must leave the request pending")
	}
}

func TestHistoryKeepsDecidedAndExpiredRequestsInOrder(t *testing.T) {
	m, clock, _, _ := setup()
	decided := submitAsync(m, "first")
	if err := m.Decide(waitPending(t, m).ID, Decision{Verdict: VerdictDeny}); err != nil {
		t.Fatal(err)
	}
	<-decided
	expired := submitAsync(m, "second")
	waitPending(t, m)
	clock.after <- clock.Now()
	<-expired
	h := m.History()
	if len(h) != 2 || h[0].Request.Scope != "first" || h[0].Decision.Verdict != VerdictDeny || h[1].Request.Scope != "second" || h[1].Decision.Verdict != VerdictNone {
		t.Fatalf("history = %+v", h)
	}
	h[0].Request.Scope = "changed"
	if m.History()[0].Request.Scope != "first" {
		t.Fatal("History must return a copy")
	}
}
