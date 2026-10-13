package approval

import "testing"

func TestDenyForTheSessionLeavesNoGrant(t *testing.T) {
	m, _, _, _ := setup()
	got := submitAsync(m, "scope")
	req := waitPending(t, m)
	if err := m.Decide(req.ID, Decision{Verdict: VerdictDeny, Lasting: LastingSession}); err != nil {
		t.Fatal(err)
	}
	if d := <-got; d.Verdict != VerdictDeny {
		t.Fatalf("decision = %+v", d)
	}
	second := submitAsync(m, "scope")
	req2 := waitPending(t, m)
	if err := m.Decide(req2.ID, Decision{Verdict: VerdictDeny}); err != nil {
		t.Fatal(err)
	}
	if d := <-second; d.Verdict != VerdictDeny || d.By == "grant" {
		t.Fatalf("a denial must not become a grant: %+v", d)
	}
}
