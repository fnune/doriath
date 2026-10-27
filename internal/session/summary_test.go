package session

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/secret"
	"github.com/fnune/doriath/internal/term"
)

func TestSummary(t *testing.T) {
	if fixed, network := summary(nil, nil); len(fixed)+len(network) != 0 {
		t.Fatalf("a quiet session must print nothing, got %v %v", fixed, network)
	}
	denied := []Denial{
		{Target: "a", Reason: "host not in the profile", Count: 5},
		{Target: "c", Reason: "refused by the profile", Count: 2},
		{Target: "/repo/.envrc", Reason: "doriath put the link back", Count: 1, Path: true},
		{Target: "b", Reason: "private address", Count: 1},
		{Target: "d", Reason: "host not in the profile", Count: 1},
	}
	history := []approval.Outcome{
		{Decision: approval.Decision{Verdict: approval.VerdictAllow}},
		{Decision: approval.Decision{Verdict: approval.VerdictDeny}},
		{Decision: approval.Decision{Verdict: approval.VerdictDeny}},
	}
	fixed, network := summary(denied, history)
	wantFixed := []note{{term.Action, "/repo/.envrc: doriath put the link back"}}
	wantNetwork := []note{
		{term.Blocked, "6 blocked: host not in the profile   a ×5, d ×1"},
		{term.Blocked, "1 blocked: private address           b ×1"},
		{term.Refused, "2 refused by the profile             c ×2"},
		{term.OK, "1 allowed, 2 denied"},
	}
	if !slices.Equal(fixed, wantFixed) {
		t.Errorf("fixed = %v, want %v", fixed, wantFixed)
	}
	if !slices.Equal(network, wantNetwork) {
		t.Errorf("network = %v, want %v", network, wantNetwork)
	}
}

func TestSummaryListsAFewHostsOfAReason(t *testing.T) {
	var denied []Denial
	for _, h := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		denied = append(denied, Denial{Target: h, Reason: "refused by the profile", Count: 1})
	}
	_, network := summary(denied, nil)
	if want := "7 refused by the profile   a ×1, b ×1, c ×1, d ×1, e ×1, and 2 more"; len(network) != 1 || network[0].text != want {
		t.Errorf("network = %v, want %q", network, want)
	}
}

func TestEndingPrintsSectionsUnderTheHeader(t *testing.T) {
	var out strings.Builder
	end := ending{
		fixed:   []note{{term.Action, "pointed it back"}},
		network: []note{{term.Refused, "1 refused by the profile   c ×1"}},
	}
	end.print(term.New(&out), "doriath log --session s1", "work", "session s1 ended")
	want := "doriath · work · session s1 ended\n" +
		"  Fixed for you\n    ↺ pointed it back\n" +
		"  Network\n    − 1 refused by the profile   c ×1\n" +
		"  → doriath log --session s1\n"
	if out.String() != want {
		t.Errorf("got\n%s\nwant\n%s", out.String(), want)
	}
}

func TestAQuietEndingPrintsNothing(t *testing.T) {
	var out strings.Builder
	ending{}.print(term.New(&out), "doriath log --session s1", "work", "session s1 ended")
	if out.Len() != 0 {
		t.Errorf("got %q", out.String())
	}
}

func TestSecretCardsAreNotCountedAsRequests(t *testing.T) {
	history := []approval.Outcome{{Request: approval.Request{Kind: approval.KindSecret}, Decision: approval.Decision{Verdict: approval.VerdictDeny}}}
	_, network := summary(nil, history)
	for _, n := range network {
		if strings.Contains(n.text, "denied") {
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
