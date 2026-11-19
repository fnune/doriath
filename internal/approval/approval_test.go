package approval

import (
	"context"
	"fmt"
	"slices"
	"strings"
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

func TestARequestAnsweredByAGrantIsRecorded(t *testing.T) {
	m, _, notifier, recorder := setup()
	got := submitAsync(m, "s")
	notifier.waitShown(t, 1)(Decision{Verdict: VerdictAllow, Lasting: LastingSession})
	<-got
	_, _ = m.Submit(context.Background(), Request{Kind: KindHTTP, Scope: "s"}, time.Minute)
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if n := len(recorder.decided); n != 2 || recorder.decided[1].By != ByGrant {
		t.Fatalf("recorded %+v", recorder.decided)
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
		{Verdict: VerdictDeny, Lasting: LastingUntil},
		{Verdict: VerdictDeny, Lasting: "forever"},
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

type repeatingIDs struct{ ids []string }

func (r *repeatingIDs) New() string {
	id := r.ids[0]
	r.ids = r.ids[1:]
	return id
}

func TestRepeatedIDsDoNotReplaceAPendingRequest(t *testing.T) {
	m := NewManager(newClock(), &fakeNotifier{}, &fakeRecorder{}, &repeatingIDs{ids: []string{"a", "a", "b"}})
	first := submitAsync(m, "one")
	waitPending(t, m)
	second := submitAsync(m, "two")
	deadline := time.Now().Add(2 * time.Second)
	for len(m.Pending()) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(m.Pending()) != 2 {
		t.Fatalf("pending = %v", m.Pending())
	}
	for id, got := range map[string]<-chan Decision{"a": first, "b": second} {
		if err := m.Decide(id, Decision{Verdict: VerdictDeny, By: "cli"}); err != nil {
			t.Fatal(err)
		}
		if d := <-got; d.Verdict != VerdictDeny {
			t.Errorf("%s: %+v", id, d)
		}
	}
}

func TestPendingRequestsAreCapped(t *testing.T) {
	m, _, _, recorder := setup()
	for i := range MaxPending {
		submitAsync(m, fmt.Sprintf("scope %d", i))
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(m.Pending()) < MaxPending && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	for range 2 {
		d, err := m.Submit(context.Background(), Request{Kind: KindHTTP, Summary: "x", Scope: "one too many"}, time.Minute)
		if err != nil || d.Verdict != VerdictDeny || !strings.Contains(d.Reason, "already waiting") {
			t.Fatalf("decision = %+v, %v", d, err)
		}
	}
	recorder.mu.Lock()
	refusals := len(recorder.decided)
	recorder.mu.Unlock()
	if refusals != 1 {
		t.Errorf("recorded %d refusals, want the first only", refusals)
	}
	if len(m.Pending()) != MaxPending {
		t.Errorf("pending = %d", len(m.Pending()))
	}
}

func TestEveryButtonOfAKindMeansADecision(t *testing.T) {
	for _, kind := range []Kind{KindHTTP, KindTool, KindHost, KindPath, KindRead, KindEdit, KindClipboard, KindSecret, KindOpen, KindForward, KindConnect} {
		for _, b := range kind.Buttons() {
			d, ok := b.Answer.Decision("test")
			if !ok || b.Label == "" || !kind.Offers(b.Answer) {
				t.Errorf("%s: button %+v means %+v, %v", kind, b, d, ok)
			}
		}
	}
	if KindHost.Offers(AnswerOnce) || KindPath.Offers(AnswerOnce) || KindRead.Offers(AnswerOnce) || KindForward.Offers(AnswerOnce) || KindConnect.Offers(AnswerOnce) {
		t.Error("a request that stays reachable once allowed offers allow once")
	}
	for _, kind := range []Kind{KindHost, KindPath, KindRead, KindForward, KindConnect} {
		if !kind.Offers(AnswerDenySession) {
			t.Errorf("%s offers an allow for the session, so it must offer a deny for the session", kind)
		}
	}
	if got := KindHost.Answered(Decision{Verdict: VerdictDeny, Lasting: LastingSession}); got != "Denied for the session" {
		t.Errorf("deny for the session answered = %q", got)
	}
	if got := KindSecret.Answered(Decision{Verdict: VerdictAllow}); got != "Tried again" {
		t.Errorf("secret answered = %q", got)
	}
}

func TestAWarnedRequestCanBeAllowedOnceOnly(t *testing.T) {
	req := Request{Kind: KindPath, Warning: "Your shells run programs from it."}
	if req.Offers(AnswerSession) || !req.Offers(AnswerOnce) || !req.Offers(AnswerDeny) {
		t.Errorf("buttons = %+v", req.Buttons())
	}
	m, _, _, _ := setup()
	got := make(chan Decision, 1)
	go func() {
		d, _ := m.Submit(context.Background(), Request{Kind: KindEdit, Summary: "x", Scope: "edit .envrc", Warning: "direnv runs it."}, time.Minute)
		got <- d
	}()
	pending := waitPending(t, m)
	for _, lasting := range []Decision{{Verdict: VerdictAllow, Lasting: LastingSession}, {Verdict: VerdictAllow, Lasting: LastingUntil, Until: time.Now().Add(time.Hour)}} {
		if err := m.Decide(pending.ID, lasting); err == nil {
			t.Errorf("a warned request was allowed %s", lasting.Lasting)
		}
	}
	if err := m.Decide(pending.ID, Decision{Verdict: VerdictAllow, Lasting: LastingOnce}); err != nil {
		t.Fatal(err)
	}
	if d := <-got; d.Verdict != VerdictAllow {
		t.Errorf("decision = %+v", d)
	}
}

func TestTheLeadCommandSkipsTheHelpersThatAProgramStartsOfItself(t *testing.T) {
	r := Request{Commands: []string{
		"/nix/store/x-chromium/libexec/chromium/chromium --type=utility --utility-sub-type=network.mojom.NetworkService",
		"/nix/store/x-chromium/libexec/chromium/.chromium-wrapped --headless=new --screenshot=page.png http://127.0.0.1:7341/",
		"timeout 40 chromium --headless=new",
		"claude",
	}}
	lead, rest := r.LeadCommand()
	if lead != r.Commands[1] {
		t.Errorf("lead = %q", lead)
	}
	if want := []string{r.Commands[0], r.Commands[2], r.Commands[3]}; !slices.Equal(rest, want) {
		t.Errorf("rest = %v", rest)
	}
	if lead, rest := (Request{Commands: []string{"gh pr edit 1", "bash"}}).LeadCommand(); lead != "gh pr edit 1" || !slices.Equal(rest, []string{"bash"}) {
		t.Errorf("lead = %q, rest = %v", lead, rest)
	}
	if lead, rest := (Request{}).LeadCommand(); lead != "" || rest != nil {
		t.Errorf("lead = %q, rest = %v", lead, rest)
	}
}

type outlineRecorder struct {
	mu      sync.Mutex
	decided []Request
}

func (*outlineRecorder) Requested(Request) {}

func (r *outlineRecorder) Decided(req Request, _ Decision) {
	r.mu.Lock()
	r.decided = append(r.decided, req)
	r.mu.Unlock()
}

func TestAGrantHitLogsNoTextFromTheAgent(t *testing.T) {
	recorder := &outlineRecorder{}
	m := NewManager(newClock(), &fakeNotifier{}, recorder, &seqIDs{})
	first := Request{Kind: KindOpen, Scope: "open evil.example", Summary: "Open a link"}
	go func() { _, _ = m.Submit(context.Background(), first, time.Minute) }()
	for len(m.Pending()) == 0 {
		time.Sleep(time.Millisecond)
	}
	if err := m.Decide(m.Pending()[0].ID, Decision{Verdict: VerdictDeny, Lasting: LastingSession}); err != nil {
		t.Fatal(err)
	}
	repeat := first
	repeat.Note, repeat.Details = strings.Repeat("A", 900<<10), strings.Repeat("B", 900<<10)
	repeat.Facts = []Fact{{Label: "Link", Value: strings.Repeat("C", 900<<10)}}
	d, _ := m.Submit(context.Background(), repeat, time.Minute)
	if d.By != ByGrant {
		t.Fatalf("decision = %+v", d)
	}
	logged := recorder.decided[len(recorder.decided)-1]
	if logged.Note != "" || logged.Details != "" || len(logged.Facts) != 0 || logged.Scope != "open evil.example" {
		t.Errorf("the log got %d bytes of the request", len(logged.Note)+len(logged.Details))
	}
}

func TestTextFromTheAgentIsCutWhenTheRequestIsSubmitted(t *testing.T) {
	m, _, notifier, _ := setup()
	req := Request{
		Kind: KindOpen, Summary: strings.Repeat("s", 1<<20), Note: strings.Repeat("n", 1<<20), Details: strings.Repeat("d", 1<<20),
		Facts:    []Fact{{Label: strings.Repeat("l", 1<<20), Value: strings.Repeat("v", 1<<20)}},
		Commands: slices.Repeat([]string{strings.Repeat("c", 1<<20)}, 100),
		Scope:    strings.Repeat("x", 1<<20),
	}
	go func() { _, _ = m.Submit(context.Background(), req, time.Minute) }()
	notifier.waitShown(t, 1)
	got := m.Pending()[0]
	total := len(got.Summary) + len(got.Note) + len(got.Details) + len(got.Facts[0].Label) + len(got.Facts[0].Value) + len(got.Scope)
	for _, c := range got.Commands {
		total += len(c)
	}
	if total > 100<<10 || len(got.Commands) > maxCommands {
		t.Errorf("a request holds %d bytes in %d commands", total, len(got.Commands))
	}
}

func TestTwoLongScopesThatDifferAtTheEndStayApart(t *testing.T) {
	m, _, _, _ := setup()
	a, b := strings.Repeat("x", 1<<20)+"a", strings.Repeat("x", 1<<20)+"b"
	go func() { _, _ = m.Submit(context.Background(), Request{Kind: KindTool, Scope: a}, time.Minute) }()
	for len(m.Pending()) == 0 {
		time.Sleep(time.Millisecond)
	}
	if err := m.Decide(m.Pending()[0].ID, Decision{Verdict: VerdictAllow, Lasting: LastingSession}); err != nil {
		t.Fatal(err)
	}
	if d, _ := m.Submit(context.Background(), Request{Kind: KindTool, Scope: a}, time.Minute); d.By != ByGrant {
		t.Errorf("the same long scope is asked again: %+v", d)
	}
	go func() { _, _ = m.Submit(context.Background(), Request{Kind: KindTool, Scope: b}, time.Minute) }()
	deadline := time.Now().Add(2 * time.Second)
	for len(m.Pending()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(m.Pending()) != 1 {
		t.Error("an allow for one long scope covered another")
	}
}
