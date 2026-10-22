//go:build integration

package session_test

import (
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/approval"
)

// TestUnknownHostIsHeldUntilYouDecide holds the connection while you answer,
// so the agent's first try works.
func TestUnknownHostIsHeldUntilYouDecide(t *testing.T) {
	e := newEnv(t)
	e.hostWait = 30 * time.Second
	code, out := e.run(e.profile(""), `
curl -sS -o /dev/null -H "Accept: text/markdown" -w "held %{http_code}\n" https://drafted.example/held
`, func() {
		e.decideNext(approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession, By: "test"})
	})
	if code != 0 || !strings.Contains(out, "held 200") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if req := e.upstream.find("/held"); req == nil || req.Header.Get("Accept") != "text/markdown" {
		t.Errorf("the held request must reach the site as sent: %+v", req)
	}
}

// TestPendingRequestCanBeAwaited refuses at once without a wait, names the
// pending approval, and lets the agent wait for it in the background.
func TestPendingRequestCanBeAwaited(t *testing.T) {
	e := newEnv(t)
	code, out := e.run(e.profile(""), `
curl -sS -o /dev/null https://drafted.example/first 2>/dev/null && echo "FAIL allowed before the decision"
/run/doriath-bin/doriath request wait drafted.example || echo "FAIL wait"
curl -sS -o /dev/null -w "after %{http_code}\n" https://drafted.example/after
`, func() {
		e.decideNext(approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession, By: "test"})
	})
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "after 200") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}
