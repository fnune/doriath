package session

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/profile"
)

type RequestOpenParams struct {
	URL string `json:"url"`
	// Reason is the agent's own text, shown to you as such.
	Reason string `json:"reason,omitempty"`
}

const (
	maxLinkLength  = 4096
	longQuery      = 200
	signInDuration = 5 * time.Minute
)

func (s *Session) requestOpen(raw, reason string) (RequestResult, error) {
	u, err := checkLink(raw)
	if err != nil {
		return RequestResult{}, err
	}
	host := strings.ToLower(u.Hostname())
	rule, ok := s.req.Profile.OpenRule(host, linkPath(u))
	if !ok {
		rule = profile.OpenRule{Action: profile.ActionApprove}
	}
	switch rule.Action {
	case profile.ActionDeny:
		return RequestResult{}, fmt.Errorf("%s: the profile refuses to open links to %s", raw, host)
	case profile.ActionAllow:
		return RequestResult{Decision: approval.Decision{Verdict: approval.VerdictAllow}}, s.openLink(u, rule.ForwardRedirect)
	}
	req := approval.Request{
		Session: s.id,
		Profile: s.req.Profile.Name,
		Kind:    approval.KindOpen,
		Summary: "Open a link to " + host + " in your browser?",
		Details: linkDetails(u),
		Note:    reason,
		URL:     u.String(),
		Scope:   "open " + host,
	}
	return s.holdAndGrant(req, func() error { return s.openLink(u, true) })
}

func checkLink(raw string) (*url.URL, error) {
	if len(raw) > maxLinkLength {
		return nil, fmt.Errorf("the link is longer than %d characters", maxLinkLength)
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("%s: doriath opens only http and https links", raw)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%s: doriath does not open a link with a user name or password in it", raw)
	}
	return u, nil
}

func linkPath(u *url.URL) string {
	return path.Clean("/" + strings.ReplaceAll(u.Path, `\`, "/"))
}

func linkDetails(u *url.URL) string {
	details := "The agent asks to open this link in your browser, where you are signed in to your own accounts:\n\n" + u.String()
	if len(u.RawQuery) > longQuery {
		details += "\n\nCareful: the link carries a long query, and your browser sends all of it to " + u.Hostname() + "."
	}
	if port := loopbackRedirect(u); port != 0 {
		details += fmt.Sprintf("\n\nThe site sends your browser back to port %d. doriath forwards that port into the jail for %s, so that the sign-in can finish.", port, signInDuration)
	}
	return details
}

func loopbackRedirect(u *url.URL) int {
	redirect, err := url.Parse(u.Query().Get("redirect_uri"))
	if err != nil || redirect.Scheme != "http" {
		return 0
	}
	switch redirect.Hostname() {
	case "localhost", "127.0.0.1", "::1":
	default:
		return 0
	}
	port, err := strconv.Atoi(redirect.Port())
	if err != nil || port < 1 || port > 65535 {
		return 0
	}
	return port
}

func (s *Session) openLink(u *url.URL, forward bool) error {
	if port := loopbackRedirect(u); forward && port != 0 {
		if err := s.forwardForSignIn(port); err != nil {
			s.log.Write("sign-in-forward-error", map[string]any{"port": port, "error": err.Error()})
		}
	}
	if s.deps.Open == nil {
		return errors.New("this session cannot open links on the host")
	}
	if err := s.deps.Open(u.String()); err != nil {
		return fmt.Errorf("open %s: %w", u.Host, err)
	}
	s.log.Write("link-opened", map[string]string{"url": u.String()})
	return nil
}

func (s *Session) forwardForSignIn(port int) error {
	reaper := int(s.peers.init.Load())
	if reaper == 0 || s.deps.Nsenter == "" {
		return errors.New("the jail is not running, or nsenter is missing")
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return err
	}
	var once sync.Once
	stop := func() { once.Do(func() { _ = ln.Close() }) }
	time.AfterFunc(signInDuration, stop)
	s.mu.Lock()
	s.signIns = append(s.signIns, stop)
	s.mu.Unlock()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.relayInto(conn.(*net.TCPConn), reaper, port)
		}
	}()
	return nil
}

func (s *Session) stopSignIns() {
	s.mu.Lock()
	stops := s.signIns
	s.signIns = nil
	s.mu.Unlock()
	for _, stop := range stops {
		stop()
	}
}

func (s *Session) relayInto(conn *net.TCPConn, reaper, port int) {
	defer func() { _ = conn.Close() }()
	f, err := conn.File()
	if err != nil {
		return
	}
	defer f.Close()
	cmd := exec.Command(s.deps.Nsenter, "--target", strconv.Itoa(reaper), "--user", "--net", "--preserve-credentials", "--",
		s.deps.Exe, "__relay", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = f, f, os.Stderr
	cmd.Env = []string{}
	_ = cmd.Run()
}
