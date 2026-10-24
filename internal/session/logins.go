package session

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/fnune/doriath/internal/oauth"
	"github.com/fnune/doriath/internal/profile"
)

func refuseOwnLogins(p *profile.Profile, stateDir string) *profile.Profile {
	out := *p
	out.HTTP = slices.Clone(p.HTTP)
	for _, m := range p.MCP {
		b, ok := p.Secrets[m.Secret]
		if m.URL == "" || !ok || b.OAuth == nil {
			continue
		}
		u, err := url.Parse(m.URL)
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		i := slices.IndexFunc(out.HTTP, func(h profile.HTTPHost) bool { return strings.EqualFold(string(h.Host), host) })
		if i < 0 {
			continue
		}
		summary := fmt.Sprintf("doriath holds the %s login for profile %s, so the agent needs none. If calls to %s fail, run on the host: doriath profiles login %s %s", m.Secret, p.Name, m.Name, p.Name, m.Secret)
		var rules []profile.Rule
		for _, path := range loginPaths(stateDir, p.SecretOwner(m.Secret), m.Secret, host) {
			if pp, err := profile.ParsePathPattern(path); err == nil {
				rules = append(rules, profile.Rule{Method: "POST", Path: pp, Action: profile.ActionDeny, Summary: summary})
			}
		}
		if wk, err := profile.ParsePathPattern("/.well-known/**"); err == nil {
			rules = append(rules, profile.Rule{Method: "GET", Path: wk, Action: profile.ActionAllow})
		}
		h := out.HTTP[i]
		h.Rules = append(rules, h.Rules...)
		out.HTTP[i] = h
	}
	return &out
}

func loginPaths(stateDir, profileName, secret, host string) []string {
	common := []string{"/token", "/oauth/token", "/register"}
	token, registration, ok := oauth.Endpoints(stateDir, profileName, secret)
	if !ok {
		return common
	}
	var paths []string
	for _, e := range []string{token, registration} {
		if u, err := url.Parse(e); err == nil && e != "" && strings.EqualFold(u.Hostname(), host) {
			paths = append(paths, u.EscapedPath())
		}
	}
	if registration == "" {
		paths = append(paths, "/register")
	}
	return paths
}
