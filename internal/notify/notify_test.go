package notify

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/approval"
)

func TestDecisionFor(t *testing.T) {
	for action, want := range map[string]approval.Decision{
		"allow-once":    {Verdict: approval.VerdictAllow, Lasting: approval.LastingOnce, By: "desktop"},
		"allow-session": {Verdict: approval.VerdictAllow, Lasting: approval.LastingSession, By: "desktop"},
		"deny":          {Verdict: approval.VerdictDeny, By: "desktop"},
	} {
		got, ok := DecisionFor(action)
		if !ok || got != want {
			t.Errorf("%s: %+v %v", action, got, ok)
		}
		if err := got.Validate(); err != nil {
			t.Errorf("%s: %v", action, err)
		}
	}
	for _, a := range []string{"open", "default", ""} {
		if _, ok := DecisionFor(a); ok {
			t.Errorf("%q must not decide", a)
		}
	}
}

func TestActionsAndBody(t *testing.T) {
	req := approval.Request{Profile: "k", Session: "s1", Details: "POST <x> & y", Expires: time.Unix(100, 0)}
	if a := Actions(req); len(a) != 6 {
		t.Errorf("actions = %v", a)
	}
	req.URL = "https://example.com"
	if a := Actions(req); len(a) != 6 {
		t.Errorf("a link the agent wrote must not get a button: %v", a)
	}
	for _, bad := range []string{"file:///etc/passwd", "javascript:alert(1)", "x-scheme:foo", "https:///nohost"} {
		req.URL = bad
		if a := Actions(req); len(a) != 6 {
			t.Errorf("%s must not get a button", bad)
		}
	}
	req.URL = "https://example.com"
	if body := Body(req); !strings.Contains(body, "POST &lt;x&gt; &amp; y") {
		t.Errorf("body = %q", body)
	}
}

func TestALinkButtonOpensOnlyAnHTTPSPageWithALabel(t *testing.T) {
	req := approval.Request{Kind: approval.KindHTTP, Link: approval.Link{Label: "Open PR", URL: "https://github.com/o/r/pull/1"}}
	if got := Actions(req); len(got) != 8 || got[0] != actionLink || got[1] != "Open PR" {
		t.Errorf("actions = %v", got)
	}
	for _, link := range []approval.Link{{Label: "Open PR", URL: "javascript:alert(1)"}, {URL: "https://github.com/o/r/pull/1"}} {
		if got := Actions(approval.Request{Kind: approval.KindHTTP, Link: link}); len(got) != 6 {
			t.Errorf("%+v: actions = %v", link, got)
		}
	}
}

func TestTheBodyLeadsWithTheFactsAndLeavesTheRestToThePage(t *testing.T) {
	req := approval.Request{
		Kind:     approval.KindHTTP,
		Session:  "s1",
		Profile:  "p",
		Action:   "Request reviews",
		Facts:    []approval.Fact{{Label: "About", Value: "repo#1"}, {Label: "userLogins", Value: "alice, <bob>"}},
		Commands: []string{"gh pr edit 1 --add-reviewer alice", "bash"},
		Details:  "POST https://api.example/graphql",
		Scope:    "http POST api.example /graphql",
		Keep:     "[[http.rules]]",
		Expires:  time.Unix(100, 0),
	}
	want := "repo#1\nuserLogins: alice, &lt;bob&gt;\n<tt>“gh pr edit 1 --add-reviewer alice”</tt>\ns1"
	if got := Body(req); got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if req.Title() != "Request reviews" {
		t.Errorf("title = %q", req.Title())
	}
}

func TestSessionWideRequestsOfferNoOneOffAllow(t *testing.T) {
	for kind, want := range map[approval.Kind][]string{
		approval.KindHost: {"allow-session", "Allow for this session", "deny-session", "Deny for this session", "deny", "Deny"},
		approval.KindPath: {"allow-session", "Allow for this session", "deny-session", "Deny for this session", "deny", "Deny"},
	} {
		if got := Actions(approval.Request{Kind: kind, URL: "https://example.com"}); !slices.Equal(got, want) {
			t.Errorf("%s: actions = %v, want %v", kind, got, want)
		}
	}
}

func TestDesktop(t *testing.T) {
	if os.Getenv("DORIATH_TEST_DESKTOP") == "" {
		t.Skip("set DORIATH_TEST_DESKTOP=1 to show a real notification")
	}
	d, err := NewDesktop()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	withdraw, err := d.Notify(context.Background(), approval.Request{Summary: "doriath test", Profile: "test", Session: "t"}, func(approval.Decision) {})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	withdraw()
}

func TestUrgency(t *testing.T) {
	if Urgency(approval.Request{Kind: approval.KindHTTP}) != urgencyHi || Urgency(approval.Request{Kind: approval.KindHost}) != urgencyNormal {
		t.Fatal("held requests are urgent, drafted rules are not")
	}
}

func TestToolRequestsAreLabeled(t *testing.T) {
	body := Body(approval.Request{Kind: approval.KindTool, Agent: "claude"})
	if !strings.Contains(body, "Written by claude, not by doriath") {
		t.Errorf("body = %q", body)
	}
}

func TestASecretCardOffersToTryAgainOrDismiss(t *testing.T) {
	got := Actions(approval.Request{Kind: approval.KindSecret})
	if len(got) != 4 || got[1] != "Try again" || got[3] != "Dismiss" {
		t.Errorf("actions = %v", got)
	}
	if got := Actions(approval.Request{Kind: approval.KindRead}); got[1] != "Allow for this session" {
		t.Errorf("read actions = %v", got)
	}
}

func TestANotificationTitleIsOneShortEscapedLine(t *testing.T) {
	got := oneLineTitle("Push\x1b]0;x\x07\nfake\u202e\u200b" + strings.Repeat("a", 200))
	if strings.ContainsAny(got, "\x1b\x07\n\u202e\u200b") || !strings.HasPrefix(got, `Push\u001b]0;x\u0007\u000afake\u202e\u200b`) {
		t.Errorf("title = %q", got)
	}
	if strings.Count(got, "a") >= 200 || !strings.HasSuffix(got, "…") {
		t.Errorf("a long title is not cut: %q", got)
	}
}

func TestAWarnedRequestShowsTheWarningFirstAndOffersNoSessionAllow(t *testing.T) {
	req := approval.Request{Kind: approval.KindPath, Profile: "work", Scope: "path write /home/u/.local/bin", Warning: "Your shells run programs from /home/u/.local/bin."}
	body := Body(req)
	if !strings.HasPrefix(body, "<b>Warning from doriath:</b> Your shells run programs") {
		t.Errorf("body = %q", body)
	}
	if strings.Contains(body, "Allow for this session") {
		t.Errorf("body = %q", body)
	}
	if got := Actions(req); len(got) != 4 || got[0] != actionAllowOnce || got[2] != actionDeny {
		t.Errorf("actions = %v", got)
	}
}

func TestTheSessionDescriptionShowsAsTheAgentsWords(t *testing.T) {
	req := approval.Request{Session: "s1", Profile: "p", Agent: "claude", Kind: approval.KindHost, SessionDescription: "Fix <b>login</b>"}
	if got := Body(req); !strings.HasSuffix(got, "<i>“Fix &lt;b&gt;login&lt;/b&gt;”</i>") {
		t.Errorf("body = %q", got)
	}
}
