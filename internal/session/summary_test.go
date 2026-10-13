package session

import (
	"strings"
	"testing"

	"github.com/fnune/girdle/internal/approval"
)

func TestSummary(t *testing.T) {
	if got := Summary("k", "s1", nil, nil); got != "" {
		t.Fatalf("a quiet session must print nothing, got %q", got)
	}
	denied := []Denial{{Host: "a", Count: 5}, {Host: "b", Count: 2}, {Host: "c", Count: 1}, {Host: "d", Count: 1}}
	history := []approval.Outcome{
		{Decision: approval.Decision{Verdict: approval.VerdictAllow}},
		{Decision: approval.Decision{Verdict: approval.VerdictDeny}},
		{Decision: approval.Decision{Verdict: approval.VerdictDeny}},
	}
	got := Summary("k", "s1", denied, history)
	for _, want := range []string{"blocked a (5), b (2), c (1), 1 more", "requests 1 allowed, 2 denied", "girdle log --session s1"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
}
