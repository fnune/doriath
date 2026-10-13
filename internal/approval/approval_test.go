package approval

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu    sync.Mutex
	now   time.Time
	after chan time.Time
}

func newClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC), after: make(chan time.Time)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(time.Duration) <-chan time.Time { return c.after }

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type fakeNotifier struct {
	mu        sync.Mutex
	shown     []Request
	respond   func(Decision)
	withdrawn int
}

func (n *fakeNotifier) Notify(_ context.Context, req Request, respond func(Decision)) (func(), error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.shown = append(n.shown, req)
	n.respond = respond
	return func() {
		n.mu.Lock()
		n.withdrawn++
		n.mu.Unlock()
	}, nil
}

func (n *fakeNotifier) waitShown(t *testing.T, count int) func(Decision) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n.mu.Lock()
		if len(n.shown) >= count {
			respond := n.respond
			n.mu.Unlock()
			return respond
		}
		n.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("notification not shown")
	return nil
}

func (n *fakeNotifier) counts() (shown, withdrawn int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.shown), n.withdrawn
}

type fakeRecorder struct {
	mu        sync.Mutex
	requested []Request
	decided   []Decision
}

func (r *fakeRecorder) Requested(req Request) {
	r.mu.Lock()
	r.requested = append(r.requested, req)
	r.mu.Unlock()
}

func (r *fakeRecorder) Decided(_ Request, d Decision) {
	r.mu.Lock()
	r.decided = append(r.decided, d)
	r.mu.Unlock()
}

type seqIDs struct{ n int }

func (s *seqIDs) New() string { s.n++; return fmt.Sprintf("r%d", s.n) }

func setup() (*Manager, *fakeClock, *fakeNotifier, *fakeRecorder) {
	clock, notifier, recorder := newClock(), &fakeNotifier{}, &fakeRecorder{}
	return NewManager(clock, notifier, recorder, &seqIDs{}), clock, notifier, recorder
}

func submitAsync(m *Manager, scope string) <-chan Decision {
	out := make(chan Decision, 1)
	go func() {
		d, _ := m.Submit(context.Background(), Request{Kind: KindHTTP, Summary: "x", Scope: scope}, time.Minute)
		out <- d
	}()
	return out
}

func waitPending(t *testing.T, m *Manager) Request {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p := m.Pending(); len(p) > 0 {
			return p[0]
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no pending request")
	return Request{}
}

func TestDecideOnceDoesNotGrant(t *testing.T) {
	m, _, notifier, recorder := setup()
	got := submitAsync(m, "scope")
	req := waitPending(t, m)
	if err := m.Decide(req.ID, Decision{Verdict: VerdictAllow, Lasting: LastingOnce, By: "cli"}); err != nil {
		t.Fatal(err)
	}
	if d := <-got; d.Verdict != VerdictAllow {
		t.Fatalf("decision = %+v", d)
	}
	if err := m.Decide(req.ID, Decision{Verdict: VerdictDeny}); err == nil {
		t.Fatal("deciding twice must fail")
	}
	second := submitAsync(m, "scope")
	req2 := waitPending(t, m)
	_ = m.Decide(req2.ID, Decision{Verdict: VerdictDeny})
	if d := <-second; d.Verdict != VerdictDeny {
		t.Fatalf("once must not leave a grant: %+v", d)
	}
	_, withdrawn := notifier.counts()
	recorder.mu.Lock()
	requested, decided := len(recorder.requested), len(recorder.decided)
	recorder.mu.Unlock()
	if withdrawn != 2 || requested != 2 || decided != 2 {
		t.Fatalf("withdrawn=%d requested=%d decided=%d", withdrawn, requested, decided)
	}
}

func TestSessionGrantAnswersLaterRequests(t *testing.T) {
	m, _, notifier, _ := setup()
	got := submitAsync(m, "POST api.github.com /repos/*/*/releases")
	respond := notifier.waitShown(t, 1)
	respond(Decision{Verdict: VerdictAllow, Lasting: LastingSession, By: "desktop"})
	if d := <-got; d.Verdict != VerdictAllow {
		t.Fatalf("decision = %+v", d)
	}
	d, err := m.Submit(context.Background(), Request{Kind: KindHTTP, Scope: "POST api.github.com /repos/*/*/releases"}, time.Minute)
	if err != nil || d.Verdict != VerdictAllow || d.By != "grant" {
		t.Fatalf("grant not used: %+v, %v", d, err)
	}
	if shown, _ := notifier.counts(); shown != 1 {
		t.Fatalf("a granted request must not notify again, shown %d", shown)
	}
}

func TestUntilGrantExpires(t *testing.T) {
	m, clock, _, _ := setup()
	got := submitAsync(m, "s")
	req := waitPending(t, m)
	_ = m.Decide(req.ID, Decision{Verdict: VerdictAllow, Lasting: LastingUntil, Until: clock.Now().Add(10 * time.Minute)})
	<-got
	clock.advance(5 * time.Minute)
	if d, _ := m.Submit(context.Background(), Request{Kind: KindHTTP, Scope: "s"}, time.Minute); d.By != "grant" {
		t.Fatalf("grant should still hold: %+v", d)
	}
	clock.advance(6 * time.Minute)
	later := submitAsync(m, "s")
	waitPending(t, m)
	clock.after <- clock.Now()
	if d := <-later; d.Verdict != VerdictNone {
		t.Fatalf("expired grant must not answer: %+v", d)
	}
}

func TestTimeoutAndCancel(t *testing.T) {
	m, clock, _, recorder := setup()
	got := submitAsync(m, "s")
	waitPending(t, m)
	clock.after <- clock.Now()
	if d := <-got; d.Verdict != VerdictNone || d.Reason == "" {
		t.Fatalf("timeout decision = %+v", d)
	}
	recorder.mu.Lock()
	decided := len(recorder.decided)
	recorder.mu.Unlock()
	if len(m.Pending()) != 0 || decided != 1 {
		t.Fatal("expired request must leave the queue and be recorded")
	}

	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan Decision, 1)
	go func() {
		d, _ := m.Submit(ctx, Request{Scope: "c"}, time.Minute)
		out <- d
	}()
	waitPending(t, m)
	cancel()
	if d := <-out; d.Verdict != VerdictNone {
		t.Fatalf("cancelled decision = %+v", d)
	}
}

func TestValidate(t *testing.T) {
	bad := []Decision{
		{Verdict: "maybe"},
		{Verdict: VerdictAllow},
		{Verdict: VerdictAllow, Lasting: LastingUntil},
	}
	for _, d := range bad {
		if d.Validate() == nil {
			t.Errorf("%+v should be invalid", d)
		}
	}
	m, _, _, _ := setup()
	if err := m.Decide("nope", Decision{Verdict: VerdictAllow}); err == nil {
		t.Fatal("invalid decision must be rejected")
	}
}

func TestGrantsDoNotCrossKinds(t *testing.T) {
	m, _, notifier, _ := setup()
	scope := "http PUT api.github.com /repos/*/*/pulls/*/merge"
	out := make(chan Decision, 1)
	go func() {
		d, _ := m.Submit(context.Background(), Request{Kind: KindTool, Summary: "harmless", Scope: scope}, time.Minute)
		out <- d
	}()
	notifier.waitShown(t, 1)(Decision{Verdict: VerdictAllow, Lasting: LastingSession, By: "test"})
	<-out
	later := make(chan Decision, 1)
	go func() {
		d, _ := m.Submit(context.Background(), Request{Kind: KindHTTP, Summary: "merge", Scope: scope}, time.Minute)
		later <- d
	}()
	respond := notifier.waitShown(t, 2)
	respond(Decision{Verdict: VerdictDeny, By: "test"})
	if d := <-later; d.Verdict != VerdictDeny || d.By == "grant" {
		t.Fatalf("a tool grant answered an HTTP request: %+v", d)
	}
}
