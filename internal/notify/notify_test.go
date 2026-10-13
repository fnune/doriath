package notify

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fnune/girdle/internal/approval"
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
	if a := Actions(req); len(a) != 8 || a[6] != "open" {
		t.Errorf("actions with URL = %v", a)
	}
	body := Body(req, time.Unix(40, 0))
	if !strings.Contains(body, "POST &lt;x&gt; &amp; y") || !strings.Contains(body, "Expires in 1m0s") {
		t.Errorf("body = %q", body)
	}
}

// TestDesktop shows a real notification and withdraws it. It only runs when
// asked, because it appears on the desktop.
func TestDesktop(t *testing.T) {
	if os.Getenv("GIRDLE_TEST_DESKTOP") == "" {
		t.Skip("set GIRDLE_TEST_DESKTOP=1 to show a real notification")
	}
	d, err := NewDesktop(nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	withdraw, err := d.Notify(context.Background(), approval.Request{Summary: "girdle test", Profile: "test", Session: "t"}, func(approval.Decision) {})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	withdraw()
}

func TestUrgency(t *testing.T) {
	if Urgency(approval.Request{Kind: approval.KindHTTP}) != urgencyHi || Urgency(approval.Request{Kind: approval.KindRule}) != urgencyNormal {
		t.Fatal("held requests are urgent, drafted rules are not")
	}
}
