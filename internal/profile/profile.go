// Package profile defines what an agent session can reach, and builds a
// Profile from TOML layers: built-in modules, user modules and the profile.
package profile

import (
	"bytes"
	"fmt"
	"path/filepath"
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
	// Ports are host loopback ports the jail reaches over HTTP, through a
	// reverse proxy that only speaks HTTP and websockets.
	Ports []int
	// TCPPorts are passed as raw TCP, for protocols such as MySQL.
	TCPPorts []int
}

// Forwards lists every forwarded port with whether it is raw TCP.
func (e Egress) Forwards() []Forward {
	out := make([]Forward, 0, len(e.Ports)+len(e.TCPPorts))
	for _, p := range e.Ports {
		out = append(out, Forward{Port: p})
	}
	for _, p := range e.TCPPorts {
		out = append(out, Forward{Port: p, TCP: true})
	}
	return out
}

type Forward struct {
	Port int
	TCP  bool
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
	// Binaries limits the credential to these programs. Other programs reach
	// the host without it. Empty means any program.
	Binaries []string
}

// trustedRoots hold programs the agent cannot write, so a program found
// there by name is the real one and not a copy the agent renamed.
var trustedRoots = []string{"/nix/store/", "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/"}

// AllowsBinary reports whether exe may use the credential. A pattern with a
// slash is a glob over the whole path. A bare name matches the file name of a
// program under a read-only system location, also in the form nix wrappers
// give it (".gh-wrapped" for "gh").
func (c Credential) AllowsBinary(exe string) bool {
	if len(c.Binaries) == 0 {
		return true
	}
	if exe == "" {
		return false
	}
	name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(exe), "."), "-wrapped")
	trusted := false
	for _, root := range trustedRoots {
		if strings.HasPrefix(exe, root) {
			trusted = true
			break
		}
	}
	for _, pattern := range c.Binaries {
		if strings.Contains(pattern, "/") {
			if ok, _ := filepath.Match(pattern, exe); ok {
				return true
			}
			continue
		}
		if trusted && pattern == name {
			return true
		}
	}
	return false
}

type Action string

const (
	ActionAllow   Action = "allow"
	ActionApprove Action = "approve"
	ActionDeny    Action = "deny"
)

type Rule struct {
	Method string
	Path   PathPattern
	// BodyContains narrows the rule to requests whose body contains one of
	// these strings, for example a GraphQL mutation name.
	BodyContains []string
	Action       Action
	Summary      string
}

// NeedsBody reports whether any rule for this host looks at request bodies.
func (h HTTPHost) NeedsBody(method, path string) bool {
	for _, r := range h.Rules {
		if len(r.BodyContains) > 0 && (r.Method == "*" || r.Method == method) && r.Path.Match(path) {
			return true
		}
	}
	return false
}

// HTTPHost is a host whose TLS traffic the proxy terminates, so that it can
// add a credential and apply per-request rules.
type HTTPHost struct {
	Host       HostPattern
	Credential *Credential
	Default    Action
	Rules      []Rule
}

// Hardening is on by default. Each switch loosens the agent jail for tools
// that need it.
type Hardening struct {
	// Namespaces lets the agent create user namespaces and mounts, which
	// nested sandboxes such as bubblewrap need.
	Namespaces bool
	Ptrace     bool
	// NoLandlock turns off Landlock's limit on where the agent can write.
	NoLandlock bool
}

type Claude struct {
	DisableConnectors bool
	// MCPServers, when set, keeps only these MCP servers from ~/.claude.json
	// in the jail's copy. Nil keeps them all.
	MCPServers []string
	StatusLine bool
	// ShareLogin gives the jail the desktop's claude.ai login, writable so
	// that token refreshes reach the desktop. Off by default: a writable
	// login lets the agent take the token, or swap in another account that
	// the desktop's sessions would then use.
	ShareLogin       bool
	DeniedMCPServers []string
	Ask              []string
	Deny             []string
	ApprovalTimeout  time.Duration
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
	Hardening   Hardening
	// NixDaemon gives the jail the system nix daemon's socket. The daemon
	// runs builds outside the jail, so they bypass the egress allowlist.
	NixDaemon bool
	Claude    Claude
	Secrets   map[string]string
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

// Decide returns the matching rule for one request to an intercepted host.
// The first matching rule wins. body is nil when no rule needs it.
func (h HTTPHost) Decide(method, path string, body []byte) (Rule, bool) {
	for _, r := range h.Rules {
		if (r.Method == "*" || r.Method == method) && r.Path.Match(path) && r.matchBody(body) {
			return r, true
		}
	}
	return Rule{Action: h.Default}, false
}

func (r Rule) matchBody(body []byte) bool {
	if len(r.BodyContains) == 0 {
		return true
	}
	for _, s := range r.BodyContains {
		if bytes.Contains(body, []byte(s)) {
			return true
		}
	}
	return false
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
