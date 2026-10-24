package session

import (
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/profile"
)

func TestOnlyPlainWebLinksAreOpened(t *testing.T) {
	for raw, want := range map[string]string{
		"file:///etc/passwd":                   "only http and https",
		"javascript:alert(1)":                  "only http and https",
		"vscode://file/x":                      "only http and https",
		"https://user:pw@example.com/":         "user name or password",
		"https://" + strings.Repeat("a", 5000): "longer than",
	} {
		if _, err := checkLink(raw); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%.40s: err = %v, want %q", raw, err, want)
		}
	}
	if _, err := checkLink("https://example.com/a?b=c"); err != nil {
		t.Errorf("a plain link: %v", err)
	}
}

func TestTheRedirectPortIsTakenOnlyFromALoopbackRedirect(t *testing.T) {
	for raw, want := range map[string]int{
		"https://claude.com/cai/oauth/authorize?redirect_uri=http%3A%2F%2Flocalhost%3A54545%2Fcallback": 54545,
		"https://auth.openai.com/oauth/authorize?redirect_uri=http://127.0.0.1:1455/auth/callback":      1455,
		"https://login.example/?redirect_uri=https://localhost:8443/cb":                                 0,
		"https://login.example/?redirect_uri=http://evil.example:80/cb":                                 0,
		"https://login.example/?redirect_uri=http://localhost/cb":                                       0,
		"https://login.example/": 0,
	} {
		u, _ := url.Parse(raw)
		if got := loopbackRedirect(u); got != want {
			t.Errorf("%s: port %d, want %d", raw, got, want)
		}
	}
}

type openedLinks struct{ urls []string }

func (o *openedLinks) open(u string) error {
	o.urls = append(o.urls, u)
	return nil
}

func linkSession(t *testing.T, notifier approval.Notifier, rules ...profile.OpenRule) (*testSession, *openedLinks) {
	t.Helper()
	s := newTestSession(t, notifier)
	opened := &openedLinks{}
	s.deps.Open = opened.open
	s.req.Profile.Open = rules
	return s, opened
}

func rule(t *testing.T, host, path string, action profile.Action) profile.OpenRule {
	t.Helper()
	h, err := profile.ParseHostPattern(host)
	if err != nil {
		t.Fatal(err)
	}
	p, err := profile.ParsePathPattern(path)
	if err != nil {
		t.Fatal(err)
	}
	return profile.OpenRule{Host: h, Path: p, Action: action}
}

func TestALinkThatARuleAllowsOpensWithoutAsking(t *testing.T) {
	notifier := &answering{seen: make(chan approval.Request, 1)}
	s, opened := linkSession(t, notifier, rule(t, "claude.com", "/cai/oauth/authorize", profile.ActionAllow))
	link := "https://claude.com/cai/oauth/authorize?client_id=x"
	if _, err := s.requestOpen(link, ""); err != nil {
		t.Fatal(err)
	}
	if len(opened.urls) != 1 || opened.urls[0] != link || len(notifier.seen) != 0 {
		t.Errorf("opened %v, asked %d times", opened.urls, len(notifier.seen))
	}
}

func TestALinkThatARuleRefusesIsNotOpened(t *testing.T) {
	s, opened := linkSession(t, &answering{}, rule(t, "*.example", "/**", profile.ActionDeny))
	if _, err := s.requestOpen("https://tracker.example/x", ""); err == nil || !strings.Contains(err.Error(), "refuses") {
		t.Errorf("err = %v", err)
	}
	if len(opened.urls) != 0 {
		t.Errorf("opened %v", opened.urls)
	}
}

func TestAnyOtherLinkAsksYouWithTheWholeLink(t *testing.T) {
	allow := approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingOnce}
	notifier := &answering{seen: make(chan approval.Request, 1), decision: &allow}
	s, opened := linkSession(t, notifier)
	link := "https://docs.example/page?q=" + strings.Repeat("x", 300)
	if _, err := s.requestOpen(link, "show the docs"); err != nil {
		t.Fatal(err)
	}
	req := <-notifier.seen
	if req.Kind != approval.KindOpen || req.Note != "show the docs" || req.Scope != "open docs.example" || !strings.Contains(req.Details, link) || !strings.Contains(req.Details, "long query") {
		t.Errorf("request = %+v", req)
	}
	if len(opened.urls) != 1 {
		t.Errorf("opened %v", opened.urls)
	}
}

func TestALinkMeetsTheRuleForThePathThatTheBrowserSends(t *testing.T) {
	notifier := denying()
	notifier.seen = make(chan approval.Request, 5)
	s, opened := linkSession(t, notifier,
		rule(t, "forge.example", "/settings/**", profile.ActionApprove),
		rule(t, "forge.example", "/**", profile.ActionAllow))
	for _, link := range []string{
		"https://forge.example/x/../settings/tokens/new",
		"https://forge.example/./settings/tokens/new",
		"https://forge.example/%2e/settings/tokens/new",
		`https://forge.example/\settings/tokens/new`,
		"https://forge.example//settings/tokens/new",
	} {
		if _, err := s.requestOpen(link, ""); err != nil {
			t.Fatal(err)
		}
	}
	if len(opened.urls) != 0 || len(notifier.seen) != 5 {
		t.Errorf("opened %v, asked %d times", opened.urls, len(notifier.seen))
	}
}

func TestASessionAllowOfAHeldLinkCoversOnlyLinksOfTheSameRule(t *testing.T) {
	notifier := allowing()
	notifier.seen = make(chan approval.Request, 4)
	s, opened := linkSession(t, notifier,
		rule(t, "forge.example", "/settings/**", profile.ActionApprove),
		rule(t, "forge.example", "/login/**", profile.ActionApprove),
		rule(t, "forge.example", "/**", profile.ActionAllow))
	for _, link := range []string{
		"https://forge.example/settings/tokens",
		"https://forge.example/settings/keys",
		"https://forge.example/login/device",
		"https://other.example/page",
	} {
		if _, err := s.requestOpen(link, ""); err != nil {
			t.Fatal(err)
		}
	}
	var scopes []string
	for len(notifier.seen) > 0 {
		scopes = append(scopes, (<-notifier.seen).Scope)
	}
	want := []string{"open forge.example /settings/**", "open forge.example /login/**", "open other.example"}
	if !slices.Equal(scopes, want) || len(opened.urls) != 4 {
		t.Errorf("asked for %q, want %q; opened %v", scopes, want, opened.urls)
	}
}
