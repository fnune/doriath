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
	body := Body(req, time.Unix(40, 0))
	if !strings.Contains(body, "POST &lt;x&gt; &amp; y") || !strings.Contains(body, "Expires in 1m0s") {
		t.Errorf("body = %q", body)
	}
}

func TestSessionWideRequestsOfferNoOneOffAllow(t *testing.T) {
	for kind, want := range map[approval.Kind][]string{
		approval.KindHost: {"allow-session", "Allow for this session", "deny", "Deny"},
		approval.KindPath: {"allow-session", "Allow for this session", "deny", "Deny"},
	} {
		if got := Actions(approval.Request{Kind: kind, URL: "https://example.com"}); !slices.Equal(got, want) {
			t.Errorf("%s: actions = %v, want %v", kind, got, want)
		}
	}
}

// TestDesktop shows a real notification and withdraws it. It only runs when
// asked, because it appears on the desktop.
func TestDesktop(t *testing.T) {
	if os.Getenv("DORIATH_TEST_DESKTOP") == "" {
		t.Skip("set DORIATH_TEST_DESKTOP=1 to show a real notification")
	}
	d, err := NewDesktop(time.Now)
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
	body := Body(approval.Request{Kind: approval.KindTool, Agent: "claude"}, time.Now())
	if !strings.Contains(body, "Written by claude, not by doriath") {
		t.Errorf("body = %q", body)
	}
}

func TestThePageBodyNamesTheProfileAndLeavesTheRestToThePage(t *testing.T) {
	got := PageBody(approval.Request{Agent: "Claude Code", Profile: "work", Details: "secret details"})
	if got != "Claude Code in profile work is waiting. Open the approvals page to answer." {
		t.Errorf("body = %q", got)
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
