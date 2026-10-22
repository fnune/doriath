// Package profile defines what an agent session can reach, and builds a
// Profile from TOML layers: built-in modules, user modules and the profile.
package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fnune/doriath/internal/secret"
)

type Mode string

const (
	ModeRead  Mode = "read"
	ModeWrite Mode = "write"
	// ModeHide shows an empty directory, or an empty file, at the path.
	ModeHide Mode = "hide"
)

type Mount struct {
	Path     string
	Mode     Mode
	Optional bool
	// Create makes doriath create the directory before the session when it
	// is missing, for writable entries inside the repository, such as an
	// agent's worktrees.
	Create bool
	// Edit says how doriath request edit changes this read-only file.
	Edit *Edit
}

// Edit is how doriath request edit changes a read-only file for the agent:
// the file's format, and the changes that need no answer from you.
type Edit struct {
	Format EditFormat
	Safe   []SafeChange
}

type EditFormat string

const (
	// FormatGitConfig compares settings, as git reads them.
	FormatGitConfig EditFormat = "git-config"
	// FormatText compares the whole file.
	FormatText EditFormat = "text"
)

// SafeChange is a setting the agent may change without asking: Key is a
// glob over git's names for settings, where * matches anything, and Value
// a pattern for each new value, where * matches anything but / and :, and
// ** anything.
type SafeChange struct {
	Key   string
	Value string
}

// Cache is a path that the jail sees as writable, backed by a directory that
// belongs to the profile, so agents never write into the desktop's caches.
type Cache struct {
	Path string
}

type Env struct {
	Set  map[string]string
	Pass []string
	// PathPrepend puts directories, such as nix store paths of tools the
	// host does not install, in front of the jail's PATH.
	PathPrepend []string
}

type Egress struct {
	Allow []HostPattern
	// Deny lists hosts refused at once, without asking you, unless an
	// allow entry names them too.
	Deny []HostPattern
	// Programs lists hosts that only some programs may reach, such as the
	// third-party hosts a browser under test loads.
	Programs []ProgramEgress
	// Ports are host loopback ports the jail reaches over HTTP, through a
	// reverse proxy that only speaks HTTP and websockets.
	Ports []int
	// TCPPorts are passed as raw TCP, for protocols such as MySQL.
	TCPPorts []int
}

// ProgramEgress lets the named programs, matched like credential binaries,
// reach hosts that other programs in the jail may not.
type ProgramEgress struct {
	Binaries []string
	Allow    []HostPattern
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
	// SchemeHeader sends the secret as the value of a header of its own,
	// such as GitLab's PRIVATE-TOKEN.
	SchemeHeader Scheme = "header"
)

type Credential struct {
	Secret   string
	Scheme   Scheme
	Username string
	// Header names the header that carries the secret for SchemeHeader.
	Header string
	// Binaries limits the credential to these programs. Other programs reach
	// the host without it. Empty means any program.
	Binaries []string
}

var trustedRoots = []string{"/nix/store/", "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/"}

// AllowsBinary reports whether exe may use the credential. A pattern with a
// slash is a glob over the whole path. A bare name matches the file name of a
// program under a read-only system location, also in the form nix wrappers
// give it (".gh-wrapped" for "gh").
func (c Credential) AllowsBinary(exe string) bool {
	if len(c.Binaries) == 0 {
		return true
	}
	return matchBinary(c.Binaries, exe)
}

// UnderTrustedRoot reports whether path lies under a system path that no
// jail can write, such as /nix/store or /usr.
func UnderTrustedRoot(path string) bool {
	for _, root := range trustedRoots {
		if strings.HasPrefix(path, root) {
			return true
		}
	}
	return false
}

func matchBinary(binaries []string, exe string) bool {
	if exe == "" {
		return false
	}
	name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(exe), "."), "-wrapped")
	trusted := UnderTrustedRoot(exe)
	for _, pattern := range binaries {
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
	// GraphQL narrows the rule by the operations a GraphQL body carries.
	GraphQL *GraphQLRule
	// Header narrows the rule to requests that carry this header, such as
	// an API key the agent brought.
	Header string
	// HeaderPrefix narrows a header rule to values that start with it,
	// ignoring case, such as "Bearer sk-ant-a" for an API key sent as a
	// bearer token.
	HeaderPrefix string
	// MCPTools narrows the rule to MCP tools/call requests for tools whose
	// names match these globs. An allow rule needs every call in the body to
	// match; other actions need one.
	MCPTools []string
	// MCPNone narrows the rule to JSON-RPC bodies that call no tool, such as
	// listing tools. A body that is not JSON-RPC does not match.
	MCPNone bool
	Action  Action
	Summary string
	// Credential replaces the host's credential for requests the rule
	// matches, for a forge whose git and API paths take different ones.
	Credential *Credential
}

// NeedsBody reports whether any rule for this host looks at request bodies.
func (h HTTPHost) NeedsBody(method, path string) bool {
	for _, r := range h.Rules {
		if (len(r.BodyContains) > 0 || r.GraphQL != nil || len(r.MCPTools) > 0 || r.MCPNone) && (r.Method == "*" || r.Method == method) && r.Path.Match(path) {
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
	// Repositories are path prefixes that name one repository, such as
	// /repos/*/* on GitHub's API. A grant for a request under one is
	// scoped to that repository.
	Repositories []PathPattern
	// SSH says that git reaches this host over SSH too. Inside the jail,
	// git sends those remotes over HTTPS instead, through the proxy.
	SSH *SSHRemote
	// EncodedSlashes lets a path segment hold %2F, as GitLab's API names a
	// project by its path. Rules then see each segment decoded on its own,
	// with the encoded slash kept, so a segment such as group%2Fproj stays
	// one segment for the rules as it does for the forge.
	EncodedSlashes bool
	Rules          []Rule
}

type SSHRemote struct {
	User string
	Port int
	// Hosts are the SSH host names of the forge, such as
	// ssh.bitbucket.org, when they differ from its HTTPS host.
	Hosts []string
}

// Repository returns the part of path that names a repository: the prefix
// one of the host's Repositories patterns matches, or, for git's smart HTTP
// protocol on any host, everything before the protocol's endpoint.
func (h HTTPHost) Repository(path string) string {
	for _, p := range h.Repositories {
		if prefix, ok := p.Prefix(path); ok {
			return prefix
		}
	}
	return gitRepository(path)
}

var gitEndpoints = []string{"/git-receive-pack", "/git-upload-pack", "/info/refs"}

func gitRepository(path string) string {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	for _, e := range gitEndpoints {
		if repo, ok := strings.CutSuffix(path, e); ok && repo != "" {
			return strings.TrimSuffix(strings.ToLower(repo), ".git")
		}
	}
	return ""
}

// Limits caps what a session can use, so a runaway agent cannot exhaust the
// workstation. Zero or empty means no limit.
type Limits struct {
	Tasks  int
	Memory string
	CPU    string
}

const (
	DefaultTaskLimit = 8192
	// DefaultMemoryLimit leaves a quarter of the RAM to the desktop, so a
	// runaway build is killed inside its own scope, not by the kernel at
	// random across the session.
	DefaultMemoryLimit = "75%"
)

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

// Agent holds what each agent adapter does alike.
type Agent struct {
	// StatusLine shows the session's profile, hosts and waiting requests
	// in the agent's status line, where the agent has one.
	StatusLine bool
	// ApprovalTimeout is how long a permission prompt waits in doriath's
	// queue before the agent shows its own.
	ApprovalTimeout time.Duration
	// Instructions are the agent's own instructions files. The jail shows
	// each as your file followed by what the session allows, for an agent
	// that doriath cannot tell at its start.
	Instructions []string
}

type Claude struct {
	DisableConnectors bool
	DeniedMCPServers  []string
	Ask               []string
	Deny              []string
}

// MCPServer is an MCP server the agent may use. A local one runs in the
// jail as Command; a remote one is reached at URL through the proxy, which
// adds Secret as a bearer token, so the agent never holds it.
type MCPServer struct {
	Name    string
	Command []string
	Env     map[string]string
	URL     string
	Secret  string
}

type Profile struct {
	Name        string
	Description string
	Mounts      []Mount
	// GitEdits are the edit rules for files in every git directory that
	// doriath guards, by file name, from mounts of {git}/NAME.
	GitEdits   map[string]*Edit
	Caches     []Cache
	Devices    []string
	Env        Env
	Egress     Egress
	HTTP       []HTTPHost
	SigningKey string
	// Unsigned says that the profile commits unsigned on purpose, even when
	// your own config signs.
	Unsigned bool
	Podman   bool
	// ContainerImages limits which images containers may use, as globs over
	// full references such as docker.io/library/*, or "*" for any image.
	// Empty allows none.
	ContainerImages []string
	Hardening       Hardening
	Limits          Limits
	// NixDaemon gives the jail the system nix daemon's socket. The daemon
	// runs builds outside the jail, so they bypass the egress allowlist.
	NixDaemon bool
	// VCSStore makes the stores of the repositories in read-only mounts
	// writable, so agents commit and add worktrees there while the
	// checkout and the files git runs stay read-only.
	VCSStore bool
	MCP      []MCPServer
	Agent    Agent
	Claude   Claude
	// Secrets says where each secret this profile uses comes from. They live
	// in the profile, not in a shared table, so a profile reaches only the
	// secrets written into it, and reusing one elsewhere is a deliberate copy.
	Secrets map[string]secret.Backend
	// Modules lists the modules the profile resolved to, in the order
	// doriath applied them.
	Modules []string
	// Sources names, for each mount, cache, host, HTTP entry, variable,
	// MCP server, image and secret, the modules or "profile" that set it.
	Sources map[string][]string
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

// AllowsHostFor reports whether the program exe may reach host: any program
// may reach the hosts AllowsHost names, and the named programs their own.
// Refuses reports whether the profile refuses host without asking you.
func (p *Profile) Refuses(host string) bool {
	return matchAny(p.Egress.Deny, host) && !p.AllowsHost(host)
}

func (p *Profile) AllowsHostFor(host, exe string) bool {
	if p.AllowsHost(host) {
		return true
	}
	for _, prog := range p.Egress.Programs {
		if matchBinary(prog.Binaries, exe) && matchAny(prog.Allow, host) {
			return true
		}
	}
	return false
}

// ProgramsFor lists the binaries that may reach a host only some programs
// may reach, for a denial that says which.
func (p *Profile) ProgramsFor(host string) []string {
	var out []string
	for _, prog := range p.Egress.Programs {
		if matchAny(prog.Allow, host) {
			out = append(out, prog.Binaries...)
		}
	}
	return out
}

func matchAny(patterns []HostPattern, host string) bool {
	for _, pattern := range patterns {
		if pattern.Match(host) {
			return true
		}
	}
	return false
}

// AllowsHost reports whether the proxy may open a connection to host for any
// program in the jail.
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
	return h.DecideRequest(method, path, nil, body)
}

// DecideRequest is Decide for a request whose headers rules may look at.
func (h HTTPHost) DecideRequest(method, path string, header http.Header, body []byte) (Rule, bool) {
	graphql := sync.OnceValues(func() ([]graphQLOperation, bool) { return parseGraphQL(body) })
	tools := sync.OnceValue(func() mcpCalls {
		t, ok := MCPToolCalls(body)
		return mcpCalls{t, ok}
	})
	for _, r := range h.Rules {
		if (r.Method == "*" || r.Method == method) && r.Path.Match(path) && r.matchHeader(header) && r.matchBody(body) && r.matchGraphQL(graphql) && r.matchMCP(tools) {
			return r, true
		}
	}
	return Rule{Action: h.Default}, false
}

func (r Rule) matchBody(body []byte) bool {
	if len(r.BodyContains) == 0 {
		return true
	}
	texts := append([][]byte{body}, jsonStrings(body)...)
	for _, s := range r.BodyContains {
		for _, t := range texts {
			if bytes.Contains(t, []byte(s)) {
				return true
			}
		}
	}
	return false
}

func (r Rule) matchGraphQL(parse func() ([]graphQLOperation, bool)) bool {
	if r.GraphQL == nil {
		return true
	}
	ops, ok := parse()
	return ok && r.GraphQL.match(ops)
}

func jsonStrings(body []byte) [][]byte {
	var doc any
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	var out [][]byte
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			out = append(out, []byte(t))
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for k, e := range t {
				out = append(out, []byte(k))
				walk(e)
			}
		}
	}
	walk(doc)
	return out
}

// HostPattern is an exact host name, or "*." followed by a domain, which
// matches every subdomain of that domain but not the domain itself. Either
// may end in ":PORT" to allow that port instead of 443 for HTTPS and 80 for
// plain HTTP, such as git.example.org:3000 for a self-hosted forge.
type HostPattern string

// Target names what a connection reaches, in the form host patterns match:
// the host alone on the default port, or host:port on any other.
func Target(host, port, defaultPort string) string {
	host = strings.ToLower(host)
	if port == "" || port == defaultPort {
		return host
	}
	return net.JoinHostPort(host, port)
}

// SplitTarget takes a target apart again. A bare IPv6 address has no port.
func SplitTarget(target string) (host, port string) {
	if h, p, err := net.SplitHostPort(target); err == nil {
		return h, p
	}
	if _, err := netip.ParseAddr(target); err == nil {
		return target, ""
	}
	host, port, _ = strings.Cut(target, ":")
	return host, port
}

var hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

func ParseHostPattern(s string) (HostPattern, error) {
	host := strings.ToLower(strings.TrimSpace(s))
	if name, port, ok := strings.Cut(host, ":"); ok {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", fmt.Errorf("host pattern %q: want a port from 1 to 65535 after the colon", s)
		}
		if _, err := ParseHostPattern(name); err != nil {
			return "", err
		}
		return HostPattern(host), nil
	}
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
	name, port := SplitTarget(strings.ToLower(host))
	name = strings.TrimSuffix(name, ".")
	pattern, wantPort, _ := strings.Cut(string(p), ":")
	if port != wantPort {
		return false
	}
	return HostPattern(pattern).matchName(name)
}

func (p HostPattern) matchName(host string) bool {
	if suffix, ok := strings.CutPrefix(string(p), "*."); ok {
		sub, ok := strings.CutSuffix(host, "."+suffix)
		return ok && !slices.Contains(strings.Split(sub, "."), "")
	}
	return host == string(p)
}

// PathPattern matches URL paths segment by segment. "*" matches one segment,
// and "**" matches any number of segments, including none, so
// "/**/git-receive-pack" matches a push to a repository at any depth.
type PathPattern string

func ParsePathPattern(s string) (PathPattern, error) {
	if !strings.HasPrefix(s, "/") {
		return "", fmt.Errorf("path pattern %q: must start with /", s)
	}
	segments := strings.Split(strings.TrimPrefix(s, "/"), "/")
	for i, seg := range segments {
		if seg == "**" && i > 0 && segments[i-1] == "**" {
			return "", fmt.Errorf("path pattern %q: ** twice in a row matches the same as once", s)
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
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	want := strings.Split(strings.TrimPrefix(string(p), "/"), "/")
	got := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(got) == 1 && got[0] == "" {
		got = nil
	}
	if len(want) == 1 && want[0] == "" {
		want = nil
	}
	consumed := make([]bool, len(got)+1)
	consumed[0] = true
	for _, seg := range want {
		next := make([]bool, len(got)+1)
		for j := range consumed {
			if !consumed[j] {
				continue
			}
			switch {
			case seg == "**":
				for k := j; k <= len(got); k++ {
					next[k] = true
				}
			case j < len(got) && (seg == "*" || strings.EqualFold(seg, got[j])):
				next[j+1] = true
			}
		}
		consumed = next
	}
	return consumed[len(got)]
}

// Prefix matches the pattern against the first segments of path, and
// returns those segments in lower case. The pattern must not hold "**".
func (p PathPattern) Prefix(path string) (string, bool) {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	want := strings.Split(strings.TrimPrefix(string(p), "/"), "/")
	got := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(got) < len(want) {
		return "", false
	}
	for i, seg := range want {
		if seg == "**" || got[i] == "" || seg != "*" && !strings.EqualFold(seg, got[i]) {
			return "", false
		}
	}
	return strings.ToLower("/" + strings.Join(got[:len(want)], "/")), true
}

func (r Rule) matchHeader(header http.Header) bool {
	if r.Header == "" {
		return true
	}
	for _, v := range header.Values(r.Header) {
		if r.HeaderPrefix == "" && v != "" || r.HeaderPrefix != "" && len(v) >= len(r.HeaderPrefix) && strings.EqualFold(v[:len(r.HeaderPrefix)], r.HeaderPrefix) {
			return true
		}
	}
	return false
}
