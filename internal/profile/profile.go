package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/fnune/doriath/internal/secret"
)

type Mode string

const (
	ModeRead  Mode = "read"
	ModeWrite Mode = "write"
	ModeHide  Mode = "hide"
)

type Missing string

const (
	MissingError Missing = "error"
	MissingSkip  Missing = "skip"
	// MissingHold puts an empty file at the path for the session when a
	// writable mount holds it, so that the agent cannot create it there.
	// Elsewhere nothing can create it, and the path is left out.
	MissingHold Missing = "hold"
)

var strictness = map[Missing]int{MissingSkip: 0, MissingHold: 1, MissingError: 2}

type Mount struct {
	Path    string
	Mode    Mode
	Missing Missing
	Create  bool
	Edit    *Edit
}

func (m Mount) OnMissing() Missing {
	switch {
	case m.Missing != "":
		return m.Missing
	case m.Mode == ModeHide:
		return MissingHold
	}
	return MissingError
}

type Edit struct {
	Format EditFormat
	Safe   []SafeChange
}

type EditFormat string

const (
	FormatGitConfig EditFormat = "git-config"
	FormatText      EditFormat = "text"
)

// SafeChange is a setting the agent may change without asking: Key is a
// glob over git's names for settings, where * matches anything, and Value
// a pattern for each new value, where * matches anything but / and :, and
// ** anything.
type SafeChange struct {
	Key   string
	Value string
}

type Cache struct {
	Path string
}

type Env struct {
	Set         map[string]string
	Pass        []string
	PathPrepend []string
}

type Egress struct {
	Allow    []HostPattern
	Deny     []HostPattern
	Programs []ProgramEgress
	Ports    []int
	TCPPorts []int
	Notes    map[HostPattern]string
}

type ProgramEgress struct {
	Binaries []string
	Allow    []HostPattern
}

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
	SchemeHeader Scheme = "header"
	// SchemeSigV4 signs each request again with AWS credentials from the
	// secret, in the JSON that credential_process prints. The agent signs
	// with placeholder keys.
	SchemeSigV4 Scheme = "sigv4"
	// SchemeWebSocket puts the token in a field of the first message that
	// the client sends on a WebSocket, in place of what the client sent. The
	// Claude in Chrome bridge takes its login in oauth_token of that message.
	SchemeWebSocket Scheme = "websocket"
)

type Credential struct {
	Secret   string
	Scheme   Scheme
	Username string
	// Field is the JSON field of the first WebSocket message that gets the
	// token, for SchemeWebSocket.
	Field string
	// KeyID is the placeholder access key that the jail signs with for
	// SchemeSigV4. A presigned URL with another key, such as one an AWS
	// service hands out, passes as it is.
	KeyID  string
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
	Method       string
	Path         PathPattern
	BodyContains []string
	// BodyLinePrefix matches a request in which a line of a JSON string or
	// form field starts with one of the prefixes, after spaces and tabs.
	BodyLinePrefix []string
	GraphQL        *GraphQLRule
	Header         string
	HeaderPrefix   string
	HeaderGlob     string
	Form           map[string]string
	// MCPTools narrows the rule to MCP tools/call requests for tools whose
	// names match these globs. An allow rule needs every call in the body to
	// match; other actions need one.
	MCPTools   []string
	MCPNone    bool
	Refs       []RefPattern
	Action     Action
	Summary    string
	Subject    Template
	Link       *RuleLink
	MCPServer  string
	Credential *Credential
}

type RuleLink struct {
	Label string
	URL   Template
}

func (h HTTPHost) NeedsBody(method, path string) bool {
	for _, r := range h.Rules {
		if (len(r.BodyContains) > 0 || len(r.BodyLinePrefix) > 0 || r.GraphQL != nil || len(r.MCPTools) > 0 || r.MCPNone) && (r.Method == "*" || r.Method == method) && r.Path.Match(path) {
			return true
		}
	}
	return false
}

func (h HTTPHost) NeedsFormBody(method, path string, header http.Header) bool {
	if !isForm(header) {
		return false
	}
	return h.Operation.Form != "" || slices.ContainsFunc(h.Rules, func(r Rule) bool {
		return (len(r.Form) > 0 || len(r.BodyLinePrefix) > 0) && (r.Method == "*" || r.Method == method) && r.Path.Match(path)
	})
}

func isForm(header http.Header) bool {
	mediaType, _, _ := mime.ParseMediaType(header.Get("Content-Type"))
	return mediaType == "application/x-www-form-urlencoded"
}

type HTTPHost struct {
	Host         HostPattern
	Credential   *Credential
	Default      Action
	Repositories []PathPattern
	SSH          *SSHRemote
	// EncodedSlashes lets a path segment hold %2F, as GitLab's API names a
	// project by its path. Rules then see each segment decoded on its own,
	// with the encoded slash kept, so a segment such as group%2Fproj stays
	// one segment for the rules as it does for the forge.
	EncodedSlashes bool
	Only           []HostPattern
	Operation      Operation
	Rules          []Rule
}

type SSHRemote struct {
	User  string
	Port  int
	Hosts []string
}

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
	path = strings.TrimSuffix(path, "/")
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
	DefaultTaskLimit   = 8192
	DefaultMemoryLimit = "75%"
)

type Hardening struct {
	Namespaces bool
	Ptrace     bool
	NoLandlock bool
}

type Agent struct {
	Instructions []string
}

type Claude struct {
	DisableConnectors bool
	DeniedMCPServers  []string
	AllowedMCPServers []string
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
	Name            string
	stateName       string
	Description     string
	Mounts          []Mount
	GitEdits        map[string]*Edit
	Caches          []Cache
	Devices         []string
	Env             Env
	Egress          Egress
	HTTP            []HTTPHost
	SigningKey      string
	Unsigned        bool
	Podman          bool
	ContainerImages []string
	Hardening       Hardening
	Limits          Limits
	// NixDaemon gives the jail the system nix daemon's socket. The daemon
	// runs builds outside the jail, so they bypass the egress allowlist.
	NixDaemon bool
	VCSStore  bool
	// ClipboardImages lets the agent ask for the image in your clipboard,
	// which you allow for each read or for the session. Text in the
	// clipboard never reaches the jail.
	ClipboardImages  bool
	MCP              []MCPServer
	Open             []OpenRule
	Forwards         []PortForward
	Agent            Agent
	Claude           Claude
	PathRules        PathRules
	Secrets          map[string]secret.Backend
	SecretOwners     map[string]string
	CodeArchives     []string
	CodeLibraries    []string
	Modules          []string
	RepositoryGrants map[string]RepositoryGrant
	Sources          map[string][]string
}

func (p *Profile) Intercepted(host string) (HTTPHost, bool) {
	for _, h := range p.HTTP {
		if h.Host.Match(host) && (len(h.Only) == 0 || matchAny(h.Only, host)) {
			return h, true
		}
	}
	return HTTPHost{}, false
}

func (p *Profile) HostNote(host string) string {
	for pattern, note := range p.Egress.Notes {
		if pattern.Match(host) {
			return note
		}
	}
	return ""
}

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

func (p *Profile) BinaryPaths() []string {
	var out []string
	add := func(binaries []string) {
		for _, b := range binaries {
			if strings.Contains(b, "/") && !slices.Contains(out, b) {
				out = append(out, b)
			}
		}
	}
	for _, prog := range p.Egress.Programs {
		add(prog.Binaries)
	}
	for _, h := range p.HTTP {
		if h.Credential != nil {
			add(h.Credential.Binaries)
		}
		for _, r := range h.Rules {
			if r.Credential != nil {
				add(r.Credential.Binaries)
			}
		}
	}
	return out
}

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

type Operation struct {
	Header string
	Form   string
}

func (h HTTPHost) OperationOf(query url.Values, header http.Header, body []byte) string {
	var parts []string
	if h.Operation.Header != "" {
		if v := header.Get(h.Operation.Header); v != "" {
			parts = append(parts, v)
		}
	}
	if h.Operation.Form != "" {
		fields, _ := formFields(query, header, body)
		if v := fields.Get(h.Operation.Form); v != "" {
			parts = append(parts, h.Operation.Form+"="+v)
		}
	}
	return strings.Join(parts, " ")
}

func (p *Profile) Label() string {
	return strings.NewReplacer("+", "-", ":", "-").Replace(p.Name)
}

func (p *Profile) SecretOwner(name string) string {
	if owner, ok := p.SecretOwners[name]; ok {
		return owner
	}
	return p.StateName()
}

// SharedOwnerPrefix starts the owner of a login that a built-in module gives.
// Every profile with the module shares that login, and no profile name has a
// colon, so the owner cannot be the name of a profile.
const SharedOwnerPrefix = "module:"

// LoginProfile is the profile to name in `doriath profiles login` for a
// secret: the one that gives it, or this profile when a module does.
func (p *Profile) LoginProfile(name string) string {
	if owner := p.SecretOwner(name); !strings.HasPrefix(owner, SharedOwnerPrefix) {
		return owner
	}
	return p.Name
}

func (p *Profile) StateName() string {
	if p.stateName != "" {
		return p.stateName
	}
	return p.Name
}

func (h HTTPHost) Decide(method, path string, body []byte) (Rule, bool) {
	return h.DecideRequest(method, path, nil, body)
}

func (h HTTPHost) DecideRequest(method, path string, header http.Header, body []byte) (Rule, bool) {
	return h.DecideWithQuery(method, path, nil, header, body)
}

func (h HTTPHost) DecideWithQuery(method, path string, query url.Values, header http.Header, body []byte) (Rule, bool) {
	return h.DecidePush(method, path, query, header, body, nil)
}

func (h HTTPHost) DecidePush(method, path string, query url.Values, header http.Header, body []byte, push *Push) (Rule, bool) {
	if reason := h.unclearOperation(method, path, query, header, body); reason != "" {
		return Rule{Action: ActionDeny, Summary: reason}, true
	}
	if h.readsMCP(method, path) {
		if _, err := jsonRPCToolCalls(body); errors.Is(err, errRepeatedKey) {
			return Rule{Action: ActionDeny, Summary: err.Error()}, true
		}
	}
	form := sync.OnceValue(func() url.Values { fields, _ := formFields(query, header, body); return fields })
	graphql := sync.OnceValues(func() ([]graphQLOperation, bool) { return parseGraphQL(body) })
	tools := sync.OnceValue(func() mcpCalls {
		t, ok := MCPToolCalls(body)
		return mcpCalls{t, ok}
	})
	for _, r := range h.Rules {
		if (r.Method == "*" || r.Method == method) && r.Path.Match(path) && r.matchHeader(header) && r.matchForm(form) && r.matchBody(body) && r.matchBodyLines(form, body) && r.matchGraphQL(graphql) && r.matchMCP(tools) && r.matchRefs(push) {
			return r, true
		}
	}
	return Rule{Action: h.Default}, false
}

func (h HTTPHost) readsMCP(method, path string) bool {
	return slices.ContainsFunc(h.Rules, func(r Rule) bool {
		return (len(r.MCPTools) > 0 || r.MCPNone) && (r.Method == "*" || r.Method == method) && r.Path.Match(path)
	})
}

func (h HTTPHost) unclearOperation(method, path string, query url.Values, header http.Header, body []byte) string {
	fields, parsed := formFields(query, header, body)
	if !parsed && h.NeedsFormBody(method, path, header) {
		return "the form body does not parse"
	}
	if h.Operation.Header != "" && len(header.Values(h.Operation.Header)) > 1 {
		return "the request names its operation in more than one " + h.Operation.Header + " header"
	}
	if h.Operation.Form != "" && len(fields[h.Operation.Form]) > 1 {
		return "the request names its operation in more than one " + h.Operation.Form + " field"
	}
	return ""
}

func (r Rule) matchBody(body []byte) bool {
	if len(r.BodyContains) == 0 {
		return true
	}
	texts := append([][]byte{body, compactJSON(body)}, jsonStrings(body)...)
	for _, s := range r.BodyContains {
		for _, t := range texts {
			if bytes.Contains(t, []byte(s)) {
				return true
			}
		}
	}
	return false
}

func (r Rule) matchBodyLines(form func() url.Values, body []byte) bool {
	if len(r.BodyLinePrefix) == 0 {
		return true
	}
	texts := append([][]byte{body}, jsonStrings(body)...)
	for _, values := range form() {
		for _, v := range values {
			texts = append(texts, []byte(v))
		}
	}
	for _, text := range texts {
		lines := strings.FieldsFunc(string(text), func(c rune) bool { return c == '\n' || c == '\r' })
		for _, line := range lines {
			line = strings.TrimLeftFunc(line, unicode.IsSpace)
			if slices.ContainsFunc(r.BodyLinePrefix, func(prefix string) bool { return strings.HasPrefix(line, prefix) }) {
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

func compactJSON(body []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var out []byte
	type level struct {
		object bool
		count  int
	}
	var stack []level
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil
		}
		if n := len(stack); n > 0 {
			top := &stack[n-1]
			if _, closing := tok.(json.Delim); !closing || tok == json.Delim('{') || tok == json.Delim('[') {
				switch {
				case top.object && top.count%2 == 1:
					out = append(out, ':')
				case top.count > 0:
					out = append(out, ',')
				}
				top.count++
			}
		}
		key := len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].count%2 == 1
		switch t := tok.(type) {
		case json.Delim:
			out = append(out, byte(t))
			switch t {
			case '{', '[':
				stack = append(stack, level{object: t == '{'})
			default:
				stack = stack[:len(stack)-1]
			}
		case string:
			if key {
				t = strings.ToLower(strings.ToUpper(t))
			}
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			if enc.Encode(t) != nil {
				return nil
			}
			out = append(out, bytes.TrimSuffix(buf.Bytes(), []byte("\n"))...)
		case json.Number:
			out = append(out, t...)
		case bool:
			out = strconv.AppendBool(out, t)
		case nil:
			out = append(out, "null"...)
		}
		if len(stack) == 0 {
			return out
		}
	}
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

type HostPattern string

func Target(host, port, defaultPort string) string {
	host = strings.ToLower(host)
	if port == "" || port == defaultPort {
		return host
	}
	return net.JoinHostPort(host, port)
}

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

func (p HostPattern) Covers(other HostPattern) bool {
	name, port := SplitTarget(string(other))
	if p == other {
		return true
	}
	if suffix, ok := strings.CutPrefix(name, "*."); ok {
		name = "covered." + suffix
	}
	return p.Match(profileTarget(name, port))
}

func profileTarget(name, port string) string {
	if port == "" {
		return name
	}
	return net.JoinHostPort(name, port)
}

func (p HostPattern) matchName(host string) bool {
	if suffix, ok := strings.CutPrefix(string(p), "*."); ok {
		sub, ok := strings.CutSuffix(host, "."+suffix)
		return ok && !slices.Contains(strings.Split(sub, "."), "")
	}
	return host == string(p)
}

// PortForward is a port on the user's machine that relays to a port in the
// jail for the whole session.
type PortForward struct {
	Name string
	Host int
	Jail int
}

func ParseForward(s string) (host, jail int, err error) {
	hostPart, jailPart, found := strings.Cut(s, ":")
	if !found {
		jailPart = hostPart
	}
	if host, err = parsePort(hostPart); err != nil {
		return 0, 0, err
	}
	if jail, err = parsePort(jailPart); err != nil {
		return 0, 0, err
	}
	return host, jail, nil
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %q: want a number from 1 to 65535", s)
	}
	return n, nil
}

type OpenRule struct {
	Host            HostPattern
	Path            PathPattern
	Action          Action
	ForwardRedirect bool
}

func (p *Profile) OpenRule(host, path string) (OpenRule, bool) {
	for _, r := range p.Open {
		if r.Host.Match(host) && r.Path.Match(path) {
			return r, true
		}
	}
	return OpenRule{}, false
}

type PathPattern string

func ParsePathPattern(s string) (PathPattern, error) {
	if !strings.HasPrefix(s, "/") {
		return "", fmt.Errorf("path pattern %q: must start with /", s)
	}
	if err := checkSegments(strings.Split(strings.TrimPrefix(s, "/"), "/")); err != nil {
		return "", fmt.Errorf("path pattern %q: %w", s, err)
	}
	return PathPattern(s), nil
}

func checkSegments(segments []string) error {
	for i, seg := range segments {
		if seg == "**" && i > 0 && segments[i-1] == "**" {
			return errors.New("** twice in a row matches the same as once")
		}
		if strings.Contains(seg, "*") && seg != "*" && seg != "**" {
			return errors.New("* must be a whole segment")
		}
	}
	return nil
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
	return matchSegments(want, got)
}

func matchSegments(want, got []string) bool {
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
		switch {
		case r.HeaderGlob != "":
			if ok, _ := path.Match(r.HeaderGlob, v); ok {
				return true
			}
		case r.HeaderPrefix != "":
			v, prefix := collapseSpace(v), collapseSpace(r.HeaderPrefix)
			if len(v) >= len(prefix) && strings.EqualFold(v[:len(prefix)], prefix) {
				return true
			}
		case v != "":
			return true
		}
	}
	return false
}

func collapseSpace(s string) string {
	var b strings.Builder
	space := false
	for _, c := range strings.TrimLeftFunc(s, unicode.IsSpace) {
		if unicode.IsSpace(c) {
			space = true
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(c)
	}
	if space {
		b.WriteByte(' ')
	}
	return b.String()
}

func (r Rule) matchForm(form func() url.Values) bool {
	if len(r.Form) == 0 {
		return true
	}
	fields := form()
	for name, glob := range r.Form {
		values, ok := fields[name]
		if !ok || !slices.ContainsFunc(values, func(v string) bool { ok, _ := path.Match(glob, v); return ok }) {
			return false
		}
	}
	return true
}

func formFields(query url.Values, header http.Header, body []byte) (url.Values, bool) {
	fields := url.Values{}
	for k, v := range query {
		fields[k] = append(fields[k], v...)
	}
	if !isForm(header) {
		return fields, true
	}
	parsed, err := url.ParseQuery(string(body))
	if err != nil {
		return fields, false
	}
	for k, v := range parsed {
		fields[k] = append(fields[k], v...)
	}
	return fields, true
}
