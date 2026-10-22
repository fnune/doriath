package session

import (
	"testing"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/term"
)

func TestSummary(t *testing.T) {
	if got := summary(nil, nil); len(got) != 0 {
		t.Fatalf("a quiet session must print nothing, got %v", got)
	}
	denied := []Denial{{Host: "a", Reason: "host not in the profile", Count: 5}, {Host: "b", Reason: "private address", Count: 1}}
	history := []approval.Outcome{
		{Decision: approval.Decision{Verdict: approval.VerdictAllow}},
		{Decision: approval.Decision{Verdict: approval.VerdictDeny}},
		{Decision: approval.Decision{Verdict: approval.VerdictDeny}},
	}
	got := summary(denied, history)
	want := []note{
		{term.Problem, "a blocked 5 times: host not in the profile"},
		{term.Problem, "b blocked 1 time: private address"},
		{term.Info, "requests: 1 allowed, 2 denied"},
	}
	if len(got) != len(want) {
		t.Fatalf("summary = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %v, want %v", i, got[i], want[i])
		}
	}
}
