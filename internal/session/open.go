package session

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/profile"
)

type RequestOpenParams struct {
	URL    string `json:"url"`
	Reason string `json:"reason,omitempty"`
}

const (
	maxLinkLength  = 4096
	longQuery      = 200
	signInDuration = 5 * time.Minute
)

func (s *Session) requestOpen(raw, reason string) (RequestResult, error) {
	if u, err := url.Parse(raw); err == nil && u.Scheme == "file" {
		return s.requestOpenFile(u, reason)
	}
	u, err := checkLink(raw)
	if err != nil {
		return RequestResult{}, err
	}
	host := strings.ToLower(u.Hostname())
	scope := "open " + host
	rule, ok := s.req.Profile.OpenRule(host, linkPath(u))
	if ok {
		scope += " " + string(rule.Path)
	} else {
		rule = profile.OpenRule{Action: profile.ActionApprove}
	}
	if rule.Action == profile.ActionDeny {
		return RequestResult{}, fmt.Errorf("%s: the profile refuses to open links to %s", raw, host)
	}
	if port := loopbackPort(u); port != 0 && !s.forwarding(port, port) {
		return s.requestOpenForwarded(u, port, reason)
	}
	if rule.Action == profile.ActionAllow {
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
		Scope:   scope,
	}
	return s.holdAndGrant(req, func() error { return s.openLink(u, true) })
}

// requestOpenForwarded asks once for both the link and the forward of its
// port: a link to a server in the jail opens nothing on your machine
// without it.
func (s *Session) requestOpenForwarded(u *url.URL, port int, reason string) (RequestResult, error) {
	req := approval.Request{
		Session: s.id,
		Profile: s.req.Profile.Name,
		Kind:    approval.KindForward,
		Summary: fmt.Sprintf("Forward port %d into the jail and open the link?", port),
		Details: "The agent asks to open this link to a server in the jail:\n\n" + u.String() + "\n\n" + forwardDetails(port, port),
		Note:    reason,
		URL:     u.String(),
		Scope:   forwardScope(port, port),
	}
	return s.holdAndGrant(req, func() error {
		if err := s.forwardPort(port, port, 0); err != nil {
			return err
		}
		return s.openLink(u, false)
	})
}

func checkLink(raw string) (*url.URL, error) {
	if len(raw) > maxLinkLength {
		return nil, fmt.Errorf("the link is longer than %d characters", maxLinkLength)
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("%s: doriath opens only http and https links, and file paths", raw)
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
	if !isLoopback(redirect.Hostname()) {
		return 0
	}
	port, err := strconv.Atoi(redirect.Port())
	if err != nil || port < 1 || port > 65535 {
		return 0
	}
	return port
}

func loopbackPort(u *url.URL) int {
	if !isLoopback(u.Hostname()) {
		return 0
	}
	if u.Port() == "" {
		if u.Scheme == "https" {
			return 443
		}
		return 80
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return 0
	}
	return port
}

func isLoopback(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

func (s *Session) openLink(u *url.URL, forward bool) error {
	if port := loopbackRedirect(u); forward && port != 0 {
		if err := s.forwardPort(port, port, signInDuration); err != nil {
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
