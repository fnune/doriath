package session

import (
	"context"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/secret"
	"github.com/fnune/doriath/internal/term"
)

func TestSummary(t *testing.T) {
	if got := summary(nil, nil); len(got) != 0 {
		t.Fatalf("a quiet session must print nothing, got %v", got)
	}
	denied := []Denial{{Host: "a", Reason: "host not in the profile", Count: 5}, {Host: "b", Reason: "private address", Count: 1}, {Host: "c", Reason: "refused by the profile", Count: 2}}
	history := []approval.Outcome{
		{Decision: approval.Decision{Verdict: approval.VerdictAllow}},
		{Decision: approval.Decision{Verdict: approval.VerdictDeny}},
		{Decision: approval.Decision{Verdict: approval.VerdictDeny}},
	}
	got := summary(denied, history)
	want := []note{
		{term.Problem, "a blocked 5 times: host not in the profile"},
		{term.Problem, "b blocked 1 time: private address"},
		{term.Refused, "c refused 2 times, as the profile says"},
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

func TestSecretCardsAreNotCountedAsRequests(t *testing.T) {
	history := []approval.Outcome{{Request: approval.Request{Kind: approval.KindSecret}, Decision: approval.Decision{Verdict: approval.VerdictDeny}}}
	for _, n := range summary(nil, history) {
		if strings.Contains(n.text, "requests:") {
			t.Errorf("a secret card counted as a request: %q", n.text)
		}
	}
}

func TestASessionStartRaisesNoSecretCard(t *testing.T) {
	s := sessionWithSecrets(t, map[string]secret.Backend{"acme": {Command: []string{"acme-token"}}})
	if err := s.fetchSecrets(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p := s.manager.Pending(); len(p) != 0 {
		t.Errorf("a card at start notifies on every session: %+v", p)
	}
}
