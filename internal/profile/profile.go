// Package profile defines what an agent session can reach, and builds a
// Profile from TOML layers: built-in modules, user modules and the profile.
package profile

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

type Mode string

const (
	ModeReadOnly  Mode = "ro"
	ModeReadWrite Mode = "rw"
)

type Mount struct {
	Path     string
	Mode     Mode
	Optional bool
}

// Cache is a path that the jail sees as writable, backed by a directory that
// belongs to the profile, so agents never write into the desktop's caches.
type Cache struct {
	Path string
}

type Env struct {
	Set  map[string]string
	Pass []string
}

type Egress struct {
	Allow []HostPattern
	Ports []int
}

type Scheme string

const (
	SchemeBearer Scheme = "bearer"
	SchemeToken  Scheme = "token"
	SchemeBasic  Scheme = "basic"
)

type Credential struct {
	Secret   string
	Scheme   Scheme
	Username string
}

type Action string

const (
	ActionAllow   Action = "allow"
	ActionApprove Action = "approve"
	ActionDeny    Action = "deny"
)

type Rule struct {
	Method  string
	Path    PathPattern
	Action  Action
	Summary string
}

// HTTPHost is a host whose TLS traffic the proxy terminates, so that it can
// add a credential and apply per-request rules.
type HTTPHost struct {
	Host       HostPattern
	Credential *Credential
	Default    Action
	Rules      []Rule
}

type Claude struct {
	DisableConnectors bool
	DeniedMCPServers  []string
	Ask               []string
	Deny              []string
	ApprovalTimeout   time.Duration
}

type Profile struct {
	Name        string
	Description string
	Match       []string
	Mounts      []Mount
	Caches      []Cache
	Devices     []string
	Env         Env
	Egress      Egress
	HTTP        []HTTPHost
	SigningKey  string
	Podman      bool
	Claude      Claude
	Secrets     map[string]string
}

// SecretName maps a secret name used by a module to the name in the user's
// secret configuration.
func (p *Profile) SecretName(name string) string {
	if alias, ok := p.Secrets[name]; ok {
		return alias
	}
	return name
}

// Intercepted returns the HTTP host entry that covers host, if any.
func (p *Profile) Intercepted(host string) (HTTPHost, bool) {
	for _, h := range p.HTTP {
		if h.Host.Match(host) {
			return h, true
		}
	}
	return HTTPHost{}, false
}

// AllowsHost reports whether the proxy may open a connection to host.
func (p *Profile) AllowsHost(host string) bool {
	if _, ok := p.Intercepted(host); ok {
		return true
	}
	for _, pattern := range p.Egress.Allow {
		if pattern.Match(host) {
			return true
		}
	}
	return false
}

// Decide returns the action and the rule summary for one request to an
// intercepted host. The first matching rule wins.
func (h HTTPHost) Decide(method, path string) (Action, string) {
	for _, r := range h.Rules {
		if (r.Method == "*" || r.Method == method) && r.Path.Match(path) {
			return r.Action, r.Summary
		}
	}
	return h.Default, ""
}

// HostPattern is an exact host name, or "*." followed by a domain, which
// matches every subdomain of that domain but not the domain itself.
type HostPattern string

var hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

func ParseHostPattern(s string) (HostPattern, error) {
	host := strings.ToLower(strings.TrimSpace(s))
	rest := strings.TrimPrefix(host, "*.")
	if rest == "" || strings.ContainsAny(rest, "*/:@") {
		return "", fmt.Errorf("host pattern %q: want a host name or *.domain", s)
	}
	for _, label := range strings.Split(rest, ".") {
		if !hostLabel.MatchString(label) {
			return "", fmt.Errorf("host pattern %q: invalid label %q", s, label)
		}
	}
	return HostPattern(host), nil
}

func (p HostPattern) Match(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if suffix, ok := strings.CutPrefix(string(p), "*."); ok {
		return strings.HasSuffix(host, "."+suffix)
	}
	return host == string(p)
}

// PathPattern matches URL paths segment by segment. "*" matches one segment
// and a trailing "**" matches the rest of the path, including nothing.
type PathPattern string

func ParsePathPattern(s string) (PathPattern, error) {
	if !strings.HasPrefix(s, "/") {
		return "", fmt.Errorf("path pattern %q: must start with /", s)
	}
	segments := strings.Split(strings.TrimPrefix(s, "/"), "/")
	for i, seg := range segments {
		if seg == "**" && i != len(segments)-1 {
			return "", fmt.Errorf("path pattern %q: ** is only allowed at the end", s)
		}
		if strings.Contains(seg, "*") && seg != "*" && seg != "**" {
			return "", fmt.Errorf("path pattern %q: * must be a whole segment", s)
		}
	}
	return PathPattern(s), nil
}

func (p PathPattern) Match(path string) bool {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	want := strings.Split(strings.TrimPrefix(string(p), "/"), "/")
	got := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, seg := range want {
		if seg == "**" {
			return true
		}
		if i >= len(got) {
			return false
		}
		if seg != "*" && seg != got[i] {
			return false
		}
	}
	return len(got) == len(want)
}
