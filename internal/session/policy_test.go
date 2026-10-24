package session

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/proxy"
)

func TestLearningModeAllowsAndRecords(t *testing.T) {
	p := &profile.Profile{Egress: profile.Egress{Allow: []profile.HostPattern{"proxy.golang.org"}}}
	strict := newLivePolicy(p, false)
	if strict.AllowsHostFor("www.kernel.org", "") || len(strict.Learned()) != 0 {
		t.Fatal("without learning mode an unknown host is refused and nothing is recorded")
	}
	learning := newLivePolicy(p, true)
	for _, h := range []string{"169.254.169.254", "10.0.0.1", "[::1]"} {
		if learning.AllowsHostFor(h, "") {
			t.Errorf("%s let through in learning mode", h)
		}
	}
	for _, h := range []string{"WWW.kernel.org", "proxy.golang.org", "www.kernel.org", "bcr.bazel.build"} {
		if !learning.AllowsHostFor(h, "") {
			t.Fatalf("%s refused in learning mode", h)
		}
	}
	if got := learning.Learned(); !slices.Equal(got, []string{"bcr.bazel.build", "www.kernel.org"}) {
		t.Fatalf("learned = %v, want only the hosts the profile does not allow", got)
	}
	learning.AllowsHostFor("js.stripe.com", "/home/u/.cache/ms-playwright/chromium-1/chrome-linux64/chrome")
	by := learning.LearnedBy()
	if !slices.Equal(by["chrome"], []string{"js.stripe.com"}) || len(by["an unidentified program"]) != 2 {
		t.Fatalf("learned by program = %v", by)
	}
}

func TestUploadWarning(t *testing.T) {
	for host, warn := range map[string]bool{
		"my-bucket.s3.amazonaws.com": true,
		"webhook.site":               true,
		"hooks.slack.com":            true,
		"registry.npmjs.org":         false,
		"notamazonaws.com":           false,
	} {
		if got := uploadWarning(host) != ""; got != warn {
			t.Errorf("%s: warning %v, want %v", host, got, warn)
		}
	}
}

func TestARefusedHostStaysRefusedWhileLearningUnlessAllowed(t *testing.T) {
	p := &profile.Profile{Egress: profile.Egress{Deny: []profile.HostPattern{"downloads.claude.ai"}}}
	if newLivePolicy(p, true).AllowsHostFor("downloads.claude.ai", "") || !p.Refuses("downloads.claude.ai") {
		t.Error("a refused host goes through in learning mode")
	}
	p.Egress.Allow = []profile.HostPattern{"downloads.claude.ai"}
	if !newLivePolicy(p, false).AllowsHostFor("downloads.claude.ai", "") || p.Refuses("downloads.claude.ai") {
		t.Error("an allow entry does not win over a deny")
	}
}

func TestHoldHostAllowsTheHostForTheRestOfTheSession(t *testing.T) {
	notifier := allowing()
	notifier.seen = make(chan approval.Request, 1)
	s := newTestSession(t, notifier)
	allowed, pending := s.HoldHost(context.Background(), "drafted.example", proxy.Identity{Exe: "/usr/bin/curl"})
	if !allowed || pending != "" {
		t.Fatalf("HoldHost = %v, %q", allowed, pending)
	}
	if !s.policy.AllowsHostFor("DRAFTED.example", "") {
		t.Error("an allowed host is still refused")
	}
	req := <-notifier.seen
	if req.Kind != approval.KindHost || req.Scope != "host egress drafted.example" || req.Summary != "Allow drafted.example for profile p?" {
		t.Errorf("request = %+v", req)
	}
	if !strings.Contains(req.Details, "curl (/usr/bin/curl) tried to reach drafted.example") {
		t.Errorf("details:\n%s", req.Details)
	}
	if req.Keep != "[egress]\nallow = [\"drafted.example\"]" {
		t.Errorf("keep = %q", req.Keep)
	}
}

// A grant answers without the decided callback, so HoldHost itself must
// open the policy before the proxy retries.
func TestHoldHostAppliesAnEarlierGrantAtOnce(t *testing.T) {
	s := newTestSession(t, allowing())
	if _, err := s.manager.Submit(context.Background(), approval.Request{Kind: approval.KindHost, Scope: "host egress Drafted.Example"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if allowed, _ := s.HoldHost(context.Background(), "Drafted.Example", proxy.Identity{}); !allowed {
		t.Fatal("the grant did not answer")
	}
	if !s.policy.AllowsHostFor("drafted.example", "") {
		t.Error("the granted host is still refused")
	}
}

func TestHoldHostRefusesWhatYouDeny(t *testing.T) {
	s := newTestSession(t, denying())
	if allowed, pending := s.HoldHost(context.Background(), "drafted.example", proxy.Identity{}); allowed || pending != "" {
		t.Fatalf("HoldHost = %v, %q", allowed, pending)
	}
	if s.policy.AllowsHostFor("drafted.example", "") {
		t.Error("a denied host is allowed")
	}
}

func TestHoldHostNamesTheRequestThatIsStillPending(t *testing.T) {
	notifier := &answering{seen: make(chan approval.Request, 1)}
	s := newTestSession(t, notifier)
	s.deps.HostWait = 0
	allowed, pending := s.HoldHost(context.Background(), "webhook.site", proxy.Identity{})
	if allowed || pending == "" {
		t.Fatalf("HoldHost = %v, %q", allowed, pending)
	}
	req := <-notifier.seen
	if !strings.HasPrefix(req.Details, "A program tried to reach webhook.site") || !strings.Contains(req.Details, "anyone can upload to webhook.site") {
		t.Errorf("details:\n%s", req.Details)
	}
	if err := s.manager.Decide(pending, approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return s.policy.AllowsHostFor("webhook.site", "") }, "an allow after the agent stopped waiting must still apply")
}

func TestEgressLinesQuoteEveryHost(t *testing.T) {
	got := egressLines([]string{"a.example", `b"c`})
	want := "[egress]\nallow = [\"a.example\", \"b\\\"c\"]"
	if got != want {
		t.Errorf("egressLines =\n%s\nwant\n%s", got, want)
	}
}

func TestAHostCardSaysWhatTheHostIsAndWhatRanTheRequest(t *testing.T) {
	notifier := allowing()
	notifier.seen = make(chan approval.Request, 1)
	s := newTestSession(t, notifier)
	pattern, err := profile.ParseHostPattern("registry.example")
	if err != nil {
		t.Fatal(err)
	}
	s.req.Profile.Egress.Notes = map[profile.HostPattern]string{pattern: "The package registry."}
	s.HoldHost(context.Background(), "registry.example", proxy.Identity{PID: 42, Exe: "/nix/store/abc-node/bin/node", Commands: []string{"node /usr/lib/npm/bin/npm-cli.js install", "sh -c npm install", "claude"}})
	req := <-notifier.seen
	for _, want := range []string{
		"registry.example: The package registry.",
		"node (/nix/store/abc-node/bin/node) tried to reach registry.example",
		"\n  node /usr/lib/npm/bin/npm-cli.js install\n  sh -c npm install\n  claude",
	} {
		if !strings.Contains(req.Details, want) {
			t.Errorf("details lack %q:\n%s", want, req.Details)
		}
	}
}

func TestTheAgentCanAskForAHostWithItsReason(t *testing.T) {
	notifier := allowing()
	notifier.seen = make(chan approval.Request, 1)
	s := newTestSession(t, notifier)
	res, err := s.requestHost("Registry.Example", "install the dependencies")
	if err != nil || res.Decision.Verdict != approval.VerdictAllow {
		t.Fatalf("res = %+v, %v", res, err)
	}
	req := <-notifier.seen
	if req.Note != "install the dependencies" || req.Scope != "host egress registry.example" || !strings.Contains(req.Details, "The agent asks to reach registry.example") {
		t.Errorf("request = %+v", req)
	}
	if !s.policy.AllowsHostFor("registry.example", "") {
		t.Error("the allowed host is still refused")
	}
}

func TestAHostRequestThatNeedsNoAnswer(t *testing.T) {
	notifier := &answering{seen: make(chan approval.Request, 1)}
	s := newTestSession(t, notifier)
	allowed, _ := profile.ParseHostPattern("allowed.example")
	refused, _ := profile.ParseHostPattern("refused.example")
	s.req.Profile.Egress.Allow = []profile.HostPattern{allowed}
	s.req.Profile.Egress.Deny = []profile.HostPattern{refused}
	s.policy = newLivePolicy(s.req.Profile, false)
	if res, err := s.requestHost("allowed.example", ""); err != nil || res.Decision.Verdict != approval.VerdictAllow {
		t.Errorf("allowed host: %+v, %v", res, err)
	}
	for host, want := range map[string]string{"refused.example": "refuses it", "*.example": "name one host", "https://x.example/": "name one host"} {
		if _, err := s.requestHost(host, ""); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", host, err, want)
		}
	}
	if len(notifier.seen) != 0 {
		t.Error("a request that needs no answer interrupted you")
	}
}
