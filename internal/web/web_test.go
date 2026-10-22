package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/approval"
)

const (
	testAddr  = "127.0.0.1:7341"
	testToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

var testNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

type fixedClock struct{}

func (fixedClock) Now() time.Time { return testNow }

type decided struct {
	session, id string
	decision    approval.Decision
}

type fakeSessions struct {
	sessions []Session
	decided  []decided
}

func (f *fakeSessions) Sessions(context.Context) ([]Session, error) { return f.sessions, nil }

func (f *fakeSessions) Decide(_ context.Context, session, id string, d approval.Decision) error {
	f.decided = append(f.decided, decided{session, id, d})
	return nil
}

type fakeHistory []Answered

func (f fakeHistory) Answered(context.Context, time.Time) ([]Answered, error) { return f, nil }

func request(id string, kind approval.Kind, summary string) approval.Request {
	return approval.Request{
		ID:         id,
		Session:    "s1",
		Profile:    "my-app",
		Kind:       kind,
		Summary:    summary,
		Scope:      "scope " + id,
		Created:    testNow.Add(-time.Minute),
		Expires:    testNow.Add(time.Hour),
		AgentWaits: testNow.Add(90 * time.Second),
	}
}

func setup(t *testing.T, reqs ...approval.Request) (*fakeSessions, http.Handler) {
	t.Helper()
	sessions := &fakeSessions{sessions: []Session{{ID: "s1", Profile: "my-app", Cwd: "/home/me/my-app", Requests: reqs}}}
	srv, err := New(sessions, fakeHistory{}, fixedClock{}, testToken, testAddr)
	if err != nil {
		t.Fatal(err)
	}
	return sessions, srv.Handler()
}

func get(h http.Handler, target string, signedIn bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Host = testAddr
	if signedIn {
		r.AddCookie(&http.Cookie{Name: cookieName, Value: testToken})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func post(h http.Handler, form url.Values, origin string, htmx bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/decide", strings.NewReader(form.Encode()))
	r.Host = testAddr
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if htmx {
		r.Header.Set("HX-Request", "true")
	}
	r.AddCookie(&http.Cookie{Name: cookieName, Value: testToken})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestNewServesOnlyOnLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:7341", "192.168.1.2:7341", "example.com:7341", "7341"} {
		if _, err := New(&fakeSessions{}, fakeHistory{}, fixedClock{}, testToken, addr); err == nil {
			t.Errorf("%s: want an error", addr)
		}
	}
	if _, err := New(&fakeSessions{}, fakeHistory{}, fixedClock{}, "short", testAddr); err == nil {
		t.Error("a short token must be refused")
	}
	if _, err := New(&fakeSessions{}, fakeHistory{}, fixedClock{}, testToken, "[::1]:7341"); err != nil {
		t.Errorf("IPv6 loopback: %v", err)
	}
}

func TestRefusesAnotherHost(t *testing.T) {
	_, h := setup(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "rebound.example:7341"
	r.AddCookie(&http.Cookie{Name: cookieName, Value: testToken})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status %d", w.Code)
	}
	for _, host := range []string{testAddr, "localhost:7341", "localhost:9000", "[::1]:7341"} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = host
		r.AddCookie(&http.Cookie{Name: cookieName, Value: testToken})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("%s: status %d", host, w.Code)
		}
	}
}

func TestTheLinkSignsTheBrowserIn(t *testing.T) {
	_, h := setup(t)
	if w := get(h, "/", false); w.Code != http.StatusUnauthorized {
		t.Fatalf("without the cookie: status %d", w.Code)
	}
	if w := get(h, "/?token=wrong", false); w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 {
		t.Fatalf("a wrong token: status %d, cookies %v", w.Code, w.Result().Cookies())
	}
	w := get(h, "/?token="+testToken, false)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("status %d, location %q", w.Code, w.Header().Get("Location"))
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Value != testToken {
		t.Fatalf("cookies %+v", cookies)
	}
	for _, path := range []string{"/main"} {
		if w := get(h, path, false); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without the cookie: status %d", path, w.Code)
		}
	}
}

func TestThePageAllowsNoInlineScript(t *testing.T) {
	_, h := setup(t)
	csp := get(h, "/", true).Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe") {
		t.Fatalf("CSP %q", csp)
	}
}

func TestAgentTextIsEscaped(t *testing.T) {
	r := request("a1", approval.KindTool, "<script>alert(1)</script> look \u202ehere")
	r.Note = `<img src=x onerror=alert(2)>`
	r.Details = "rm -rf build\x1b[2J"
	_, h := setup(t, r)
	body := get(h, "/", true).Body.String()
	for _, raw := range []string{"<script>alert", "<img src=x", "\u202e", "\x1b"} {
		if strings.Contains(body, raw) {
			t.Errorf("page holds %q unescaped", raw)
		}
	}
	for _, shown := range []string{"&lt;script&gt;", `\u202e`, `\u001b`, "Written by the agent, not by doriath."} {
		if !strings.Contains(body, shown) {
			t.Errorf("page lacks %q", shown)
		}
	}
}

func TestPageShowsWaitingAndParked(t *testing.T) {
	waiting := request("a1", approval.KindHTTP, "Merge pull request #412")
	parked := request("a2", approval.KindHost, "Allow registry.npmjs.org for profile my-app?")
	parked.AgentWaits = testNow.Add(-time.Second)
	parked.Keep = "[egress]\nallow = [\"registry.npmjs.org\"]"
	_, h := setup(t, waiting, parked)
	body := get(h, "/", true).Body.String()
	if !strings.Contains(body, "1:30") || !strings.Contains(body, "The agent is waiting for your answer, 1:30 left.") {
		t.Error("the waiting request shows no time left")
	}
	if !strings.Contains(body, "parked") {
		t.Error("the parked request is not shown as parked")
	}
	body = get(h, "/?request=s1/a2", true).Body.String()
	if !strings.Contains(body, "The agent stopped waiting") || !strings.Contains(body, "allow = [&#34;registry.npmjs.org&#34;]") {
		t.Error("the parked request's detail lacks its status or profile lines")
	}
	if strings.Contains(body, `value="once"`) {
		t.Error("a host request offers allow once")
	}
}

func TestDecideNeedsThisPagesOrigin(t *testing.T) {
	sessions, h := setup(t, request("a1", approval.KindHTTP, "Merge"))
	form := url.Values{"session": {"s1"}, "id": {"a1"}, "answer": {"once"}}
	for _, origin := range []string{"", "http://evil.example", "null", "http://127.0.0.1:9999"} {
		if w := post(h, form, origin, false); w.Code != http.StatusForbidden {
			t.Errorf("origin %q: status %d", origin, w.Code)
		}
	}
	if len(sessions.decided) != 0 {
		t.Fatalf("decided %+v", sessions.decided)
	}
	w := post(h, form, "http://"+testAddr, false)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	want := decided{"s1", "a1", approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingOnce, By: "web"}}
	if len(sessions.decided) != 1 || sessions.decided[0] != want {
		t.Fatalf("decided %+v", sessions.decided)
	}
}

func TestDecideRefusesWhatTheRequestDoesNotOffer(t *testing.T) {
	sessions, h := setup(t, request("a1", approval.KindHost, "Allow a.example?"), request("a2", approval.KindPath, "Let the agent write /x"))
	for _, form := range []url.Values{
		{"session": {"s1"}, "id": {"a1"}, "answer": {"once"}},
		{"session": {"s1"}, "id": {"a2"}, "answer": {"once"}},
		{"session": {"s1"}, "id": {"a1"}, "answer": {"forever"}},
		{"session": {"s1"}, "id": {"gone"}, "answer": {"deny"}},
		{"session": {"s2"}, "id": {"a1"}, "answer": {"deny"}},
	} {
		if w := post(h, form, "http://"+testAddr, false); w.Code != http.StatusConflict {
			t.Errorf("%v: status %d", form, w.Code)
		}
	}
	if len(sessions.decided) != 0 {
		t.Fatalf("decided %+v", sessions.decided)
	}
}

func TestDecideFromHtmxReturnsTheMainPart(t *testing.T) {
	sessions, h := setup(t, request("a1", approval.KindPath, "Let the agent write /x"))
	w := post(h, url.Values{"session": {"s1"}, "id": {"a1"}, "answer": {"session"}}, "http://"+testAddr, true)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.HasPrefix(body, `<div id="main"`) {
		t.Fatalf("status %d, body %.80q", w.Code, body)
	}
	if len(sessions.decided) != 1 || sessions.decided[0].decision.Lasting != approval.LastingSession {
		t.Fatalf("decided %+v", sessions.decided)
	}
	w = post(h, url.Values{"session": {"s1"}, "id": {"gone"}, "answer": {"deny"}}, "http://"+testAddr, true)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "request gone is no longer waiting") {
		t.Fatalf("an error must show in the swapped part: status %d", w.Code)
	}
}

func TestProofNeedsTheToken(t *testing.T) {
	_, h := setup(t)
	challenge := "0123456789abcdef"
	w := get(h, "/proof?challenge="+challenge, false)
	if w.Code != http.StatusOK || w.Body.String() != Proof(testToken, challenge) {
		t.Fatalf("status %d, body %q", w.Code, w.Body)
	}
	if Proof("another token", challenge) == Proof(testToken, challenge) {
		t.Fatal("the proof does not depend on the token")
	}
	if w := get(h, "/proof?challenge=short", false); w.Code != http.StatusBadRequest {
		t.Fatalf("short challenge: status %d", w.Code)
	}
}

func TestAnsweredShowsTheVerdictAndWhoGaveIt(t *testing.T) {
	sessions := &fakeSessions{}
	history := fakeHistory{
		{Time: testNow.Add(-6 * time.Minute), Request: request("b1", approval.KindHTTP, "Push to fnune/my-app"), Decision: approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession, By: "desktop"}},
		{Time: testNow.Add(-time.Hour), Request: request("b2", approval.KindHost, "Allow t.example?"), Decision: approval.Decision{Verdict: approval.VerdictNone}},
	}
	srv, err := New(sessions, history, fixedClock{}, testToken, testAddr)
	if err != nil {
		t.Fatal(err)
	}
	body := get(srv.Handler(), "/", true).Body.String()
	for _, want := range []string{"Allowed for the session", "6 min ago", "Answered on the desktop", "No answer in time", "No sessions running"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

type failingSessions struct{ fakeSessions }

func (failingSessions) Sessions(context.Context) ([]Session, error) {
	return nil, errors.New("no runtime directory")
}

func TestAFailureShowsOnThePage(t *testing.T) {
	srv, err := New(&failingSessions{}, fakeHistory{}, fixedClock{}, testToken, testAddr)
	if err != nil {
		t.Fatal(err)
	}
	if body := get(srv.Handler(), "/", true).Body.String(); !strings.Contains(body, "read the running sessions: no runtime directory") {
		t.Fatal("the page hides the failure")
	}
}

func TestVendoredScriptsMatchTheirPins(t *testing.T) {
	for path, want := range map[string]string{
		"assets/vendor/htmx.min.js":          "d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717",
		"assets/vendor/idiomorph-ext.min.js": "5811b9a7eda14878b7dab4378bf60432e1bb6f11fcfb970cc26540642650181e",
	} {
		data, err := assets.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != want {
			t.Errorf("%s changed; update its pin in assets/vendor/README.md and here", path)
		}
	}
}
