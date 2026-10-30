package approval

import (
	"context"
	"testing"
	"time"
)

func TestADenyForTheSessionNeverAllows(t *testing.T) {
	m, _, notifier, _ := setup()
	got := submitAsync(m, "scope")
	req := waitPending(t, m)
	if err := m.Decide(req.ID, Decision{Verdict: VerdictDeny, Lasting: LastingSession}); err != nil {
		t.Fatal(err)
	}
	if d := <-got; d.Verdict != VerdictDeny {
		t.Fatalf("decision = %+v", d)
	}
	d, err := m.Submit(context.Background(), Request{Kind: KindHTTP, Scope: "scope"}, time.Minute)
	if err != nil || d.Verdict != VerdictDeny || d.By != ByGrant || d.Reason == "" {
		t.Fatalf("a later request must be denied at once, with a reason: %+v, %v", d, err)
	}
	if shown, _ := notifier.counts(); shown != 1 {
		t.Fatalf("a request denied for the session must not notify again, shown %d", shown)
	}
}

func TestAPlainDenyLeavesNoGrant(t *testing.T) {
	m, _, _, _ := setup()
	got := submitAsync(m, "scope")
	req := waitPending(t, m)
	if err := m.Decide(req.ID, Decision{Verdict: VerdictDeny}); err != nil {
		t.Fatal(err)
	}
	<-got
	second := submitAsync(m, "scope")
	req2 := waitPending(t, m)
	if err := m.Decide(req2.ID, Decision{Verdict: VerdictDeny}); err != nil {
		t.Fatal(err)
	}
	if d := <-second; d.By == ByGrant {
		t.Fatalf("a plain deny must not answer later requests: %+v", d)
	}
}
