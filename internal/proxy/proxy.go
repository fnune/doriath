package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/cli"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/secret"
)

type Policy interface {
	AllowsHostFor(host, exe string) bool
	ProgramsFor(host string) []string
	Refuses(host string) bool
	Intercepted(host string) (profile.HTTPHost, bool)
}

type HostHolder interface {
	HoldHost(ctx context.Context, host string, caller Identity) (allowed bool, pending string)
}

type WaitNotifier interface {
	Waiting(caller Identity, summary string)
}

type Approver interface {
	Submit(ctx context.Context, req approval.Request, ttl time.Duration) (approval.Decision, error)
}

type Secrets interface {
	Get(ctx context.Context, name string) (secret.Value, error)
}

// Rejecter is a store that wants to hear that a server refused a token, so
// that its next answer holds a newer token. Get answers a login that another
// process refreshed, or refreshes it.
type Rejecter interface {
	Reject(name, token string)
}

type Issuer interface {
	Certificate(host string) (*tls.Certificate, error)
}

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Event struct {
	Kind   string `json:"kind"`
	Host   string `json:"host"`
	Exe    string `json:"exe,omitempty"`
	Port   string `json:"port,omitempty"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	Action string `json:"action,omitempty"`
	Status int    `json:"status,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type Recorder interface {
	Egress(e Event)
}

type Config struct {
	Session string
	Profile string
	// ApprovalTTL bounds how long a request waits for a decision. The
	// client's connection stays open while it waits.
	ApprovalTTL time.Duration
	// UpstreamRoots verifies upstream servers. Nil means the system roots.
	UpstreamRoots *x509.CertPool
	// Holder, when set, asks you about hosts the profile does not name
	// instead of refusing them at once.
	Holder       HostHolder
	Waiting      WaitNotifier
	WaitingAfter time.Duration
}

type Server struct {
	cfg      Config
	policy   Policy
	approver Approver
	secrets  Secrets
	issuer   Issuer
	dialer   Dialer
	recorder Recorder

	transport *http.Transport

	mu   sync.Mutex
	seen map[string]bool
}

func New(cfg Config, policy Policy, approver Approver, secrets Secrets, issuer Issuer, dialer Dialer, recorder Recorder) *Server {
	s := &Server{
		cfg:      cfg,
		policy:   policy,
		approver: approver,
		secrets:  secrets,
		issuer:   issuer,
		dialer:   dialer,
		recorder: recorder,
		seen:     map[string]bool{},
	}
	s.transport = &http.Transport{
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{RootCAs: cfg.UpstreamRoots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return s
}

func (s *Server) Serve(l net.Listener) error {
	srv := &http.Server{
		Handler:           http.HandlerFunc(s.handle),
		ReadHeaderTimeout: 30 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return withIdentity(ctx, connIdentity(c))
		},
	}
	err := srv.Serve(l)
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.connect(w, r)
		return
	}
	switch {
	case r.URL.Host == "":
		deny(w, http.StatusBadRequest, "doriath: this is a forward proxy; send absolute URLs or CONNECT")
	case r.URL.Scheme == "http":
		s.plain(w, r)
	case r.URL.Scheme == "https":
		s.absoluteHTTPS(w, r)
	default:
		deny(w, http.StatusBadRequest, fmt.Sprintf("doriath: unsupported scheme %q", r.URL.Scheme))
	}
}

func (s *Server) absoluteHTTPS(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.URL.Hostname())
	target := profile.Target(host, r.URL.Port(), "443")
	if !s.admit(w, r, target, r.URL.Port()) {
		return
	}
	r.Host = target
	r.Header.Del("Proxy-Authorization")
	if rules, ok := s.policy.Intercepted(target); ok {
		s.firstSeen(target, "intercept")
		s.intercepted(w, r, host, target, rules)
		return
	}
	s.firstSeen(target, "https")
	s.forward(w, r, "https", target)
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		deny(w, http.StatusBadRequest, "doriath: CONNECT needs host:port")
		return
	}
	host = strings.ToLower(host)
	target := profile.Target(host, port, "443")
	if !s.admit(w, r, target, port) {
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		deny(w, http.StatusInternalServerError, "doriath: connection cannot be hijacked")
		return
	}
	if intercept, ok := s.policy.Intercepted(target); ok {
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			_ = conn.Close()
			return
		}
		s.firstSeen(target, "intercept")
		s.intercept(prefixed(conn, buf.Reader), host, target, intercept, IdentityFrom(r.Context()))
		return
	}

	upstream, err := s.dialer.DialContext(r.Context(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		s.record(Event{Kind: "error", Host: host, Port: port, Reason: err.Error()})
		deny(w, http.StatusBadGateway, fmt.Sprintf("doriath: cannot reach %s: %v", host, err))
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = conn.Close()
		_ = upstream.Close()
		return
	}
	client := prefixed(conn, buf.Reader)
	name, hello, isTLS := peekServerName(client)
	if reason := tunnelMismatch(host, name, isTLS); reason != "" {
		s.record(Event{Kind: "denied", Host: host, Port: port, Exe: IdentityFrom(r.Context()).Exe, Reason: reason})
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	if _, err := upstream.Write(hello); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	s.firstSeen(target, "tunnel")
	pipe(client, upstream)
}

func (s *Server) intercept(conn net.Conn, host, target string, rules profile.HTTPHost, id Identity) {
	tlsConn := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := strings.ToLower(hello.ServerName)
			if name != "" && name != host {
				return nil, fmt.Errorf("SNI %q does not match CONNECT host %q", name, host)
			}
			return s.issuer.Certificate(host)
		},
	})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.intercepted(w, r, host, target, rules)
	})
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
		ConnContext:       func(ctx context.Context, _ net.Conn) context.Context { return withIdentity(ctx, id) },
		Protocols:         &protocols,
	}
	_ = srv.Serve(newOneConnListener(tlsConn))
}

func (s *Server) intercepted(w http.ResponseWriter, r *http.Request, host, target string, rules profile.HTTPHost) {
	reqHost := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(reqHost); err == nil {
		reqHost = h
	}
	if reqHost != host {
		s.record(Event{Kind: "denied", Host: host, Method: r.Method, Path: r.URL.Path, Reason: "Host header " + r.Host + " differs from the tunnel"})
		deny(w, http.StatusMisdirectedRequest, "doriath: the Host header must match the tunneled host")
		return
	}
	if r.Method != strings.ToUpper(r.Method) {
		s.record(Event{Kind: "denied", Host: host, Method: r.Method, Path: r.URL.Path, Reason: "method is not upper case"})
		deny(w, http.StatusBadRequest, "doriath: HTTP methods must be upper case")
		return
	}
	reqPath, ok := matchPath(r.URL, rules.EncodedSlashes)
	if !ok {
		s.record(Event{Kind: "denied", Host: host, Method: r.Method, Path: r.URL.Path, Reason: "path is not in canonical form"})
		deny(w, http.StatusBadRequest, "doriath: the request path must be in canonical form (no //, ./, ../ or encoded slashes)")
		return
	}
	var body []byte
	needsBody := rules.NeedsBody(r.Method, reqPath) || rules.NeedsFormBody(r.Method, reqPath, r.Header)
	if needsBody && !identityEncoding(r.Header.Get("Content-Encoding")) {
		s.record(Event{Kind: "denied", Host: host, Method: r.Method, Path: reqPath, Reason: "compressed body on an inspected request"})
		deny(w, http.StatusUnsupportedMediaType, "doriath: send this request uncompressed, so its body can be checked")
		return
	}
	if needsBody {
		var tooLarge bool
		var err error
		body, tooLarge, err = readBody(r, maxInspectedBody)
		if err != nil {
			deny(w, http.StatusBadRequest, "doriath: cannot read the request body")
			return
		}
		if tooLarge {
			s.record(Event{Kind: "denied", Host: host, Method: r.Method, Path: reqPath, Reason: "request body too large to inspect"})
			deny(w, http.StatusRequestEntityTooLarge, "doriath: request body too large to inspect")
			return
		}
	}
	refs, unread := pushedRefs(r)
	push := pushOf(refs, unread)
	rule, matched := rules.DecidePush(r.Method, reqPath, r.URL.Query(), r.Header, body, push)
	action, summary := rule.Action, rule.Summary
	switch action {
	case profile.ActionDeny:
		s.record(Event{Kind: "denied", Host: host, Method: r.Method, Path: reqPath, Action: string(action), Reason: summary})
		msg := fmt.Sprintf("doriath: %s %s%s is not allowed by profile %q", r.Method, host, reqPath, s.cfg.Profile)
		if summary != "" {
			msg += ": " + summary
		}
		deny(w, http.StatusForbidden, msg)
		return
	case profile.ActionApprove:
		operation := rules.OperationOf(r.URL.Query(), r.Header, body)
		if summary == "" {
			summary = fmt.Sprintf("%s %s%s", r.Method, host, reqPath)
			if operation != "" {
				summary += " " + operation
			}
		} else if repo := rules.Repository(reqPath); repo != "" {
			summary += " in " + host + repo
		}
		if tools := profile.DescribeMCP(body); len(rule.MCPTools) > 0 && tools != "" {
			summary += " " + tools
		}
		details := fmt.Sprintf("%s https://%s%s%s", r.Method, host, r.URL.RequestURI(), caller(r.Context()))
		if push != nil {
			var names []string
			for _, u := range refs {
				names = append(names, u.short())
				details += "\n" + u.line()
			}
			if unread {
				names = append(names, unreadRefs)
				details += "\n" + unreadRefs
			}
			summary += ": " + strings.Join(names, ", ")
		}
		shown := body
		if shown == nil && push == nil {
			shown = peekBody(r, maxShownBody)
		}
		desc := describe(httpRequest{rule: rule, matched: matched, method: r.Method, host: host, path: reqPath, repo: rules.Repository(reqPath), operation: operation, body: shown, refs: refs, unread: unread, caller: IdentityFrom(r.Context())})
		stopHint := s.hintWhenHeld(r.Context(), summary)
		d, err := s.approver.Submit(r.Context(), approval.Request{
			Session:  s.cfg.Session,
			Profile:  s.cfg.Profile,
			Kind:     approval.KindHTTP,
			Summary:  summary,
			Action:   desc.action,
			Facts:    desc.facts,
			Commands: desc.commands,
			Link:     desc.link,
			Details:  details + bodyExcerpt(shown),
			Scope:    scope(rule, matched, r.Method, reqPath, host, body, push, rules.Repository(reqPath), operation),
		}, s.cfg.ApprovalTTL)
		stopHint()
		if err != nil || d.Verdict != approval.VerdictAllow {
			reason, message := "denied", fmt.Sprintf("doriath: %s was denied", summary)
			if d.Verdict == approval.VerdictNone {
				reason = "nobody approved it in time"
				message = fmt.Sprintf("doriath: %s: %s", summary, reason)
			}
			s.record(Event{Kind: "denied", Host: host, Method: r.Method, Path: reqPath, Action: string(action), Reason: reason})
			if d.Reason != "" && d.Verdict == approval.VerdictDeny {
				message += ": " + d.Reason
			}
			deny(w, http.StatusForbidden, message)
			return
		}
		s.record(Event{Kind: "approved", Host: host, Method: r.Method, Path: reqPath, Reason: summary})
	}

	c := rules.Credential
	if matched && rule.Credential != nil {
		c = rule.Credential
	}
	var sign signOnTheWayOut
	var rejected func()
	switch {
	case c == nil:
	case !c.AllowsBinary(IdentityFrom(r.Context()).Program()):
		s.withheld(host, IdentityFrom(r.Context()))
	case c.Scheme == profile.SchemeWebSocket:
		if isWebSocketUpgrade(r) {
			s.forwardWebSocket(w, r, target, *c)
			return
		}
	case c.Scheme == profile.SchemeSigV4:
		var err error
		sign, err = s.sigv4(r.Context(), *c, r)
		if err != nil && !errors.Is(err, errUnsignedGoesAsItCame) {
			s.record(Event{Kind: "denied", Host: host, Method: r.Method, Path: reqPath, Reason: err.Error()})
			deny(w, http.StatusBadRequest, "doriath: cannot sign this request for "+host+": "+err.Error())
			return
		}
	default:
		name, value, err := s.credentialHeader(r.Context(), *c)
		if rej, ok := s.secrets.(Rejecter); ok && err == nil {
			rejected = func() { rej.Reject(c.Secret, tokenOf(value)) }
		}
		if err != nil {
			s.record(Event{Kind: "error", Host: host, Method: r.Method, Path: r.URL.Path, Reason: err.Error()})
			deny(w, http.StatusBadGateway, fmt.Sprintf("doriath: cannot load the credential for %s: %v", host, err))
			return
		}
		if name != "Authorization" {
			r.Header.Del("Authorization")
		}
		r.Header.Set(name, value)
	}
	s.forwardAudited(w, r, target, sign, rejected)
}

func (s *Server) plain(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.URL.Hostname())
	target := profile.Target(host, r.URL.Port(), "80")
	if _, ok := s.policy.Intercepted(target); ok {
		s.record(Event{Kind: "denied", Host: target, Method: r.Method, Path: r.URL.Path, Reason: "plain HTTP to an intercepted host"})
		deny(w, http.StatusForbidden, fmt.Sprintf("doriath: use https for %s", target))
		return
	}
	if !s.admit(w, r, target, r.URL.Port()) {
		return
	}
	s.firstSeen(target, "http")
	r.Header.Del("Proxy-Authorization")
	s.forward(w, r, "http", r.URL.Host)
}

// tokenOf is the token in the value of an Authorization header.
func tokenOf(header string) string {
	_, token, found := strings.Cut(header, " ")
	if !found {
		return header
	}
	return token
}

// forwardAudited sends the request on. When the server answers 401 to a
// request that carried a credential, rejected runs, so that the next request
// does not carry the same token again.
func (s *Server) forwardAudited(w http.ResponseWriter, r *http.Request, host string, sign signOnTheWayOut, rejected func()) {
	exe := IdentityFrom(r.Context()).Exe
	s.forwardWith(w, r, "https", host, sign, func(resp *http.Response) error {
		s.record(Event{Kind: "request", Host: host, Method: r.Method, Path: r.URL.Path, Exe: exe, Status: resp.StatusCode})
		if resp.StatusCode == http.StatusUnauthorized && rejected != nil {
			rejected()
		}
		return nil
	})
}

func (s *Server) forward(w http.ResponseWriter, r *http.Request, scheme, host string) {
	s.forwardWith(w, r, scheme, host, nil, nil)
}

func (s *Server) forwardWith(w http.ResponseWriter, r *http.Request, scheme, host string, sign signOnTheWayOut, onResponse func(*http.Response) error) {
	var transport http.RoundTripper = s.transport
	if sign != nil {
		transport = signingTransport{base: s.transport, sign: sign}
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = scheme
			pr.Out.URL.Host = host
			pr.Out.Host = host
			pr.Out.Header.Del("Proxy-Authorization")
			pr.Out.Header.Del("Proxy-Connection")
		},
		Transport:      transport,
		FlushInterval:  -1,
		ModifyResponse: onResponse,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.record(Event{Kind: "error", Host: host, Method: r.Method, Path: r.URL.Path, Reason: err.Error()})
			deny(w, http.StatusBadGateway, fmt.Sprintf("doriath: upstream %s failed: %v", host, err))
		},
		// The default logger writes to the terminal that the agent shares.
		ErrorLog: log.New(eventLog{s: s, host: host, method: r.Method, path: r.URL.Path}, "", 0),
	}
	rp.ServeHTTP(noCloseNotify{w}, r.WithContext(context.WithoutCancel(r.Context())))
}

type eventLog struct {
	s                  *Server
	host, method, path string
}

func (l eventLog) Write(p []byte) (int, error) {
	l.s.record(Event{Kind: "error", Host: l.host, Method: l.method, Path: l.path, Reason: strings.TrimSpace(string(p))})
	return len(p), nil
}

type noCloseNotify struct{ http.ResponseWriter }

func (w noCloseNotify) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) credentialHeader(ctx context.Context, c profile.Credential) (string, string, error) {
	v, err := s.secrets.Get(ctx, c.Secret)
	if err != nil {
		return "", "", unavailable(err)
	}
	token := string(v.Reveal())
	switch c.Scheme {
	case profile.SchemeBasic:
		return "Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+token)), nil
	case profile.SchemeToken:
		return "Authorization", "token " + token, nil
	case profile.SchemeHeader:
		return c.Header, token, nil
	default:
		return "Authorization", "Bearer " + token, nil
	}
}

func unavailable(err error) error {
	return fmt.Errorf("%w. doriath tries again within 30 seconds", err)
}

func scope(r profile.Rule, matched bool, method, path, host string, body []byte, push *profile.Push, repo, operation string) string {
	if !matched {
		s := fmt.Sprintf("http %s %s %s", method, host, scopePath(path))
		if gql := profile.DescribeGraphQL(body); gql != "" {
			s += " graphql " + gql
		}
		if operation != "" {
			s += " operation " + operation
		}
		return s
	}
	s := fmt.Sprintf("http %s %s %s", r.Method, host, string(r.Path))
	if len(r.BodyContains) > 0 {
		s += " " + strings.Join(r.BodyContains, ",")
	}
	if r.GraphQL != nil {
		s += " " + r.GraphQL.String()
	}
	if len(r.MCPTools) > 0 {
		tools, _ := profile.MCPToolCalls(body)
		for i, t := range tools {
			tools[i] = url.PathEscape(t)
		}
		s += " mcp " + strings.Join(tools, ", ")
	}
	if len(r.Refs) > 0 && push != nil {
		pushed := slices.Clone(push.Refs)
		if push.Unread {
			pushed = append(pushed, unreadRefs)
		}
		s += " refs " + strings.Join(pushed, ", ")
	}
	if r.HeaderGlob != "" {
		s += " " + r.Header + "=" + r.HeaderGlob
	}
	for _, name := range slices.Sorted(maps.Keys(r.Form)) {
		s += " " + name + "=" + r.Form[name]
	}
	if repo != "" {
		s += " in " + scopePath(repo)
	}
	return s
}

func scopePath(p string) string {
	return strings.ReplaceAll((&url.URL{Path: p}).EscapedPath(), "*", "%2A")
}

const excerptLimit = 400

func bodyExcerpt(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	text := string(body)
	var gql struct {
		Query     string          `json:"query"`
		Variables json.RawMessage `json:"variables"`
	}
	if json.Unmarshal(body, &gql) == nil && gql.Query != "" {
		text = gql.Query
		if len(gql.Variables) > 0 && string(gql.Variables) != "null" {
			text += "\nvariables " + string(gql.Variables)
		}
	}
	if len(text) > excerptLimit {
		text = text[:excerptLimit] + "…"
	}
	return "\n" + text
}

const maxInspectedBody = 1 << 20

const maxShownBody = 64 << 10

func peekBody(r *http.Request, limit int64) []byte {
	if r.Body == nil || !identityEncoding(r.Header.Get("Content-Encoding")) {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(data), r.Body), r.Body}
	if err != nil || int64(len(data)) > limit {
		return nil
	}
	return data
}

func readBody(r *http.Request, limit int64) ([]byte, bool, error) {
	if r.Body == nil {
		return nil, false, nil
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return nil, true, nil
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(data))
	r.ContentLength = int64(len(data))
	return data, false, nil
}

func (s *Server) withheld(host string, id Identity) {
	exe := id.Exe
	if exe == "" {
		exe = "an unidentified program"
	}
	reason := "not allowed for " + exe
	if id.Untrusted != "" {
		reason = id.Untrusted
	}
	s.mu.Lock()
	key := "withheld " + host + " " + reason
	first := !s.seen[key]
	s.seen[key] = true
	s.mu.Unlock()
	if first {
		s.record(Event{Kind: "credential-withheld", Host: host, Exe: id.Exe, Reason: reason})
	}
}

func caller(ctx context.Context) string {
	if exe := IdentityFrom(ctx).Exe; exe != "" {
		return " from " + exe
	}
	return ""
}

func (s *Server) firstSeen(host, kind string) {
	s.mu.Lock()
	key := kind + " " + host
	first := !s.seen[key]
	s.seen[key] = true
	s.mu.Unlock()
	if first {
		s.record(Event{Kind: kind, Host: host})
	}
}

func (s *Server) record(e Event) {
	if s.recorder != nil {
		s.recorder.Egress(e)
	}
}

func deny(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Doriath-Denied", "1")
	body, _ := json.Marshal(map[string]string{"message": message})
	w.Header().Set("Content-Length", strconv.Itoa(len(body)+1))
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}

func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

func matchPath(u *url.URL, encodedSlashes bool) (string, bool) {
	raw := strings.ToLower(u.EscapedPath())
	if strings.Contains(raw, "%5c") || strings.Contains(raw, "%00") || strings.Contains(u.Path, "\\") || strings.Contains(u.Path, ";") {
		return "", false
	}
	p := u.Path
	if strings.Contains(raw, "%2f") {
		if !encodedSlashes {
			return "", false
		}
		segments := strings.Split(u.EscapedPath(), "/")
		for i, seg := range segments {
			kept := strings.NewReplacer("%2F", "\x00", "%2f", "\x00").Replace(seg)
			decoded, err := url.PathUnescape(kept)
			if err != nil || strings.Contains(decoded, "/") {
				return "", false
			}
			for _, part := range strings.Split(decoded, "\x00") {
				if part == "." || part == ".." {
					return "", false
				}
			}
			segments[i] = strings.ReplaceAll(decoded, "\x00", "%2F")
		}
		p = strings.Join(segments, "/")
	}
	if p == "" || p == "/" {
		return p, true
	}
	clean := path.Clean(p)
	return p, p == clean || (clean != "/" && p == clean+"/")
}

func identityEncoding(enc string) bool {
	enc = strings.TrimSpace(strings.ToLower(enc))
	return enc == "" || enc == "identity"
}

func (s *Server) hintWhenHeld(ctx context.Context, summary string) (stop func()) {
	if s.cfg.Waiting == nil {
		return func() {}
	}
	caller := IdentityFrom(ctx)
	t := time.AfterFunc(s.cfg.WaitingAfter, func() { s.cfg.Waiting.Waiting(caller, summary) })
	return func() { t.Stop() }
}

const ReasonNotInProfile = "host not in the profile"

func (s *Server) admit(w http.ResponseWriter, r *http.Request, host, port string) bool {
	exe := IdentityFrom(r.Context()).Exe
	if s.policy.AllowsHostFor(host, IdentityFrom(r.Context()).Program()) {
		return true
	}
	reason := s.hostReason(host)
	if reason == ReasonNotInProfile && s.cfg.Holder != nil {
		allowed, id := s.cfg.Holder.HoldHost(r.Context(), host, IdentityFrom(r.Context()))
		if allowed {
			return true
		}
		if id != "" {
			s.record(Event{Kind: "denied", Host: host, Port: port, Exe: exe, Reason: reason})
			deny(w, http.StatusForbidden, fmt.Sprintf("doriath: %s is not in profile %q, and approval %s is pending. To wait for the answer, run: %s", host, s.cfg.Profile, id, cli.Code(cli.Line("request", "wait", host))))
			return false
		}
	}
	s.record(Event{Kind: "denied", Host: host, Port: port, Exe: exe, Reason: reason})
	s.denyHost(w, host)
	return false
}

const ReasonRefused = "refused by the profile"

func (s *Server) hostReason(host string) string {
	if s.policy.Refuses(host) {
		return ReasonRefused
	}
	if progs := s.policy.ProgramsFor(host); len(progs) > 0 {
		return "host allowed only for " + strings.Join(progs, ", ")
	}
	return ReasonNotInProfile
}

func (s *Server) denyHost(w http.ResponseWriter, host string) {
	if s.policy.Refuses(host) {
		deny(w, http.StatusForbidden, fmt.Sprintf("doriath: profile %q refuses %s; work without it", s.cfg.Profile, host))
		return
	}
	if progs := s.policy.ProgramsFor(host); len(progs) > 0 {
		deny(w, http.StatusForbidden, fmt.Sprintf("doriath: profile %q lets only %s reach %s", s.cfg.Profile, strings.Join(progs, ", "), host))
		return
	}
	deny(w, http.StatusForbidden, fmt.Sprintf("doriath: %s is not in profile %q; add it to [egress] allow if the agent needs it", host, s.cfg.Profile))
}

func tunnelMismatch(host, name string, isTLS bool) string {
	switch {
	case !isTLS:
		return "the tunnel did not start with a TLS ClientHello"
	case name == "":
		if net.ParseIP(host) != nil {
			return ""
		}
		return "the TLS ClientHello names no server"
	case !strings.EqualFold(strings.TrimSuffix(name, "."), host):
		return fmt.Sprintf("TLS server name %s does not match the tunnel's host", name)
	}
	return ""
}
