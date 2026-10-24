package session

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/profile"
)

func TestTheLoopbackPortIsTakenFromTheLinkItself(t *testing.T) {
	for raw, want := range map[string]int{
		"http://localhost:4321/":       4321,
		"http://127.0.0.1:8080/a?b=c":  8080,
		"http://[::1]:3000/":           3000,
		"http://LOCALHOST/":            80,
		"https://localhost/":           443,
		"http://docs.example:4321/":    0,
		"http://localhost.example:80/": 0,
	} {
		u, _ := url.Parse(raw)
		if got := loopbackPort(u); got != want {
			t.Errorf("%s: port %d, want %d", raw, got, want)
		}
	}
}

func TestALinkToTheJailAsksToForwardItsPortFirst(t *testing.T) {
	notifier := &answering{seen: make(chan approval.Request, 1), decision: &approval.Decision{Verdict: approval.VerdictDeny}}
	s, opened := linkSession(t, notifier, rule(t, "localhost", "/**", profile.ActionAllow))
	link := "http://localhost:4321/docs/"
	if _, err := s.requestOpen(link, "preview the docs"); err != nil {
		t.Fatal(err)
	}
	req := <-notifier.seen
	if req.Kind != approval.KindForward || req.Scope != "forward 4321:4321" || req.URL != link || req.Note != "preview the docs" || !strings.Contains(req.Details, "until the session ends") {
		t.Errorf("request = %+v", req)
	}
	if len(opened.urls) != 0 {
		t.Errorf("opened %v after a deny", opened.urls)
	}
}

func TestALinkToAForwardedPortFollowsTheOpenRules(t *testing.T) {
	notifier := &answering{seen: make(chan approval.Request, 1)}
	s, opened := linkSession(t, notifier, rule(t, "localhost", "/**", profile.ActionAllow))
	s.hostForwards = map[int]*hostForward{4321: {jailPort: 4321}}
	if _, err := s.requestOpen("http://localhost:4321/", ""); err != nil {
		t.Fatal(err)
	}
	if len(opened.urls) != 1 || len(notifier.seen) != 0 {
		t.Errorf("opened %v, asked %d times", opened.urls, len(notifier.seen))
	}
}

func TestALinkToTheJailThatARuleRefusesIsNotForwarded(t *testing.T) {
	notifier := &answering{seen: make(chan approval.Request, 1)}
	s, _ := linkSession(t, notifier, rule(t, "localhost", "/**", profile.ActionDeny))
	if _, err := s.requestOpen("http://localhost:4321/", ""); err == nil || !strings.Contains(err.Error(), "refuses") {
		t.Errorf("err = %v", err)
	}
	if len(notifier.seen) != 0 {
		t.Error("asked to forward a port whose link the profile refuses")
	}
}

func TestAForwardAsksOnceAndNotAgainWhileItLasts(t *testing.T) {
	notifier := &answering{seen: make(chan approval.Request, 1), decision: &approval.Decision{Verdict: approval.VerdictDeny}}
	s := newTestSession(t, notifier)
	if _, err := s.requestForward(8080, 4321, "preview"); err != nil {
		t.Fatal(err)
	}
	if req := <-notifier.seen; req.Kind != approval.KindForward || req.Scope != "forward 8080:4321" || !strings.Contains(req.Details, "127.0.0.1:8080") {
		t.Errorf("request = %+v", req)
	}
	s.hostForwards = map[int]*hostForward{8080: {jailPort: 4321}}
	res, err := s.requestForward(8080, 4321, "")
	if err != nil || res.Decision.Verdict != approval.VerdictAllow || len(notifier.seen) != 0 {
		t.Errorf("a lasting forward asked again: %+v, %v", res, err)
	}
	if got := s.lastingForwards(); len(got) != 1 || got[0] != (StatusForward{Host: 8080, Jail: 4321}) {
		t.Errorf("lasting forwards = %+v", got)
	}
}

func TestAForwardRefusesAPortOutOfRange(t *testing.T) {
	s := newTestSession(t, &answering{})
	for _, ports := range [][2]int{{0, 80}, {80, 70000}} {
		if _, err := s.requestForward(ports[0], ports[1], ""); err == nil {
			t.Errorf("%v: no error", ports)
		}
	}
}

func TestALastingForwardTakesOverASignInForwardUntilTheSessionEnds(t *testing.T) {
	s := newTestSession(t, &answering{})
	s.peers.init.Store(1)
	s.deps.Nsenter = "nsenter"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	if err := s.forwardPort(port, port, time.Hour); err != nil {
		t.Fatal(err)
	}
	if s.forwarding(port, port) {
		t.Error("a sign-in forward counts as lasting")
	}
	if err := s.forwardPort(port, port, 0); err != nil || !s.forwarding(port, port) {
		t.Errorf("the lasting forward did not take over: %v", err)
	}
	if err := s.forwardPort(port, port+1, 0); err == nil || !strings.Contains(err.Error(), "already forwards") {
		t.Errorf("a second jail port on the same host port: %v", err)
	}
	s.stopForwards()
	ln, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("the port stayed open after the session: %v", err)
	}
	_ = ln.Close()
}
