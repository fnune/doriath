// Package proxy is the jail's only way to the network. It tunnels connections
// to allowed hosts, refuses everything else, and terminates TLS for
// intercepted hosts so that it can add credentials and apply request rules.
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
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fnune/girdle/internal/approval"
	"github.com/fnune/girdle/internal/profile"
	"github.com/fnune/girdle/internal/secret"
)

type Policy interface {
	// AllowsHostFor reports whether the program exe may reach host.
	AllowsHostFor(host, exe string) bool
	// ProgramsFor names the programs that alone may reach host, if any.
	ProgramsFor(host string) []string
	Intercepted(host string) (profile.HTTPHost, bool)
}

type Approver interface {
	Submit(ctx context.Context, req approval.Request, ttl time.Duration) (approval.Decision, error)
}

type Secrets interface {
	Get(ctx context.Context, name string) (secret.Value, error)
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

// Serve accepts proxy clients until the listener closes.
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
		deny(w, http.StatusBadRequest, "girdle: this is a forward proxy; send absolute URLs or CONNECT")
	case r.URL.Scheme == "http":
		s.plain(w, r)
	case r.URL.Scheme == "https":
		s.absoluteHTTPS(w, r)
	default:
		deny(w, http.StatusBadRequest, fmt.Sprintf("girdle: unsupported scheme %q", r.URL.Scheme))
	}
}

func (s *Server) absoluteHTTPS(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.URL.Hostname())
	if port := r.URL.Port(); port != "" && port != "443" {
		s.record(Event{Kind: "denied", Host: host, Port: port, Reason: "only port 443 is proxied for HTTPS"})
		deny(w, http.StatusForbidden, fmt.Sprintf("girdle: port %s is not allowed", port))
		return
	}
	if !s.policy.AllowsHostFor(host, IdentityFrom(r.Context()).Exe) {
		s.record(Event{Kind: "denied", Host: host, Exe: IdentityFrom(r.Context()).Exe, Reason: s.hostReason(host)})
		s.denyHost(w, host)
		return
	}
	r.Host = host
	r.Header.Del("Proxy-Authorization")
	if rules, ok := s.policy.Intercepted(host); ok {
		s.firstSeen(host, "intercept")
		s.intercepted(w, r, host, rules)
		return
	}
	s.firstSeen(host, "https")
	s.forward(w, r, "https", host)
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		deny(w, http.StatusBadRequest, "girdle: CONNECT needs host:port")
		return
	}
	host = strings.ToLower(host)
	if port != "443" {
		s.record(Event{Kind: "denied", Host: host, Port: port, Reason: "only port 443 is tunneled"})
		deny(w, http.StatusForbidden, fmt.Sprintf("girdle: port %s is not allowed; only HTTPS on 443 goes through the proxy", port))
		return
	}
	if !s.policy.AllowsHostFor(host, IdentityFrom(r.Context()).Exe) {
		s.record(Event{Kind: "denied", Host: host, Port: port, Exe: IdentityFrom(r.Context()).Exe, Reason: s.hostReason(host)})
		s.denyHost(w, host)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		deny(w, http.StatusInternalServerError, "girdle: connection cannot be hijacked")
		return
	}
	if intercept, ok := s.policy.Intercepted(host); ok {
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			_ = conn.Close()
			return
		}
		s.firstSeen(host, "intercept")
		s.intercept(prefixed(conn, buf.Reader), host, intercept, IdentityFrom(r.Context()))
		return
	}

	upstream, err := s.dialer.DialContext(r.Context(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		s.record(Event{Kind: "error", Host: host, Port: port, Reason: err.Error()})
		deny(w, http.StatusBadGateway, fmt.Sprintf("girdle: cannot reach %s: %v", host, err))
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
	name, hello := peekServerName(client)
	if name != "" && !strings.EqualFold(strings.TrimSuffix(name, "."), host) {
		s.record(Event{Kind: "denied", Host: host, Port: port, Exe: IdentityFrom(r.Context()).Exe, Reason: fmt.Sprintf("TLS server name %s does not match the tunnel's host", name)})
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	if _, err := upstream.Write(hello); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	s.firstSeen(host, "tunnel")
	pipe(client, upstream)
}

func (s *Server) intercept(conn net.Conn, host string, rules profile.HTTPHost, id Identity) {
	tlsConn := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := strings.ToLower(hello.ServerName)
			if name != "" && name != host {
				return nil, fmt.Errorf("SNI %q does not match CONNECT host %q", name, host)
			}
			return s.issuer.Certificate(host)
		},
	})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.intercepted(w, r, host, rules)
	})
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
		ConnContext:       func(ctx context.Context, _ net.Conn) context.Context { return withIdentity(ctx, id) },
	}
	_ = srv.Serve(newOneConnListener(tlsConn))
}

func (s *Server) intercepted(w http.ResponseWriter, r *http.Request, host string, rules profile.HTTPHost) {
	reqHost := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(reqHost); err == nil {
		reqHost = h
	}
	if reqHost != host {
		s.record(Event{Kind: "denied", Host: host, Method: r.Method, Path: r.URL.Path, Reason: "Host header " + r.Host + " differs from the tunnel"})
		deny(w, http.StatusMisdirectedRequest, "girdle: the Host header must match the tunneled host")
		return
	}
	if r.Method != strings.ToUpper(r.Method) {
		s.record(Event{Kind: "denied", Host: host, Method: r.Method, Path: r.URL.Path, Reason: "method is not upper case"})
		deny(w, http.StatusBadRequest, "girdle: HTTP methods must be upper case")
		return
	}
	if !canonicalPath(r.URL) {
		s.record(Event{Kind: "denied", Host: host, Method: r.Method, Path: r.URL.Path, Reason: "path is not in canonical form"})
		deny(w, http.StatusBadRequest, "girdle: the request path must be in canonical form (no //, ./, ../ or encoded slashes)")
		return
	}
	var body []byte
	if rules.NeedsBody(r.Method, r.URL.Path) && !identityEncoding(r.Header.Get("Content-Encoding")) {
		s.record(Event{Kind: "denied", Host: host, Method: r.Method, Path: r.URL.Path, Reason: "compressed body on an inspected request"})
		deny(w, http.StatusUnsupportedMediaType, "girdle: send this request uncompressed, so its body can be checked")
		return
	}
	if rules.NeedsBody(r.Method, r.URL.Path) {
		var tooLarge bool
		var err error
		body, tooLarge, err = readBody(r, maxInspectedBody)
		if err != nil {
			deny(w, http.StatusBadRequest, "girdle: cannot read the request body")
			return
		}
		if tooLarge {
			s.record(Event{Kind: "denied", Host: host, Method: r.Method, Path: r.URL.Path, Reason: "request body too large to inspect"})
			deny(w, http.StatusRequestEntityTooLarge, "girdle: request body too large to inspect")
			return
		}
	}
	rule, matched := rules.Decide(r.Method, r.URL.Path, body)
	action, summary := rule.Action, rule.Summary
	switch action {
	case profile.ActionDeny:
		s.record(Event{Kind: "denied", Host: host, Method: r.Method, Path: r.URL.Path, Action: string(action), Reason: summary})
		deny(w, http.StatusForbidden, fmt.Sprintf("girdle: %s %s%s is not allowed by profile %q", r.Method, host, r.URL.Path, s.cfg.Profile))
		return
	case profile.ActionApprove:
		if summary == "" {
			summary = fmt.Sprintf("%s %s%s", r.Method, host, r.URL.Path)
		}
		d, err := s.approver.Submit(r.Context(), approval.Request{
			Session: s.cfg.Session,
			Profile: s.cfg.Profile,
			Kind:    approval.KindHTTP,
			Summary: summary,
			Details: fmt.Sprintf("%s https://%s%s%s%s", r.Method, host, r.URL.RequestURI(), caller(r.Context()), bodyExcerpt(body)),
			Scope:   scope(rule, matched, r.Method, r.URL.Path, host, body),
		}, s.cfg.ApprovalTTL)
		if err != nil || d.Verdict != approval.VerdictAllow {
			reason := "denied"
			if d.Verdict == approval.VerdictNone {
				reason = "nobody approved it in time"
			}
			s.record(Event{Kind: "denied", Host: host, Method: r.Method, Path: r.URL.Path, Action: string(action), Reason: reason})
			message := fmt.Sprintf("girdle: %s was %s", summary, reason)
			if d.Reason != "" && d.Verdict == approval.VerdictDeny {
				message += ": " + d.Reason
			}
			deny(w, http.StatusForbidden, message)
			return
		}
		s.record(Event{Kind: "approved", Host: host, Method: r.Method, Path: r.URL.Path, Reason: summary})
	}

	if c := rules.Credential; c != nil && !c.AllowsBinary(IdentityFrom(r.Context()).Exe) {
		s.withheld(host, IdentityFrom(r.Context()))
	} else if c != nil {
		header, err := s.authorization(r.Context(), *c)
		if err != nil {
			s.record(Event{Kind: "error", Host: host, Method: r.Method, Path: r.URL.Path, Reason: err.Error()})
			deny(w, http.StatusBadGateway, fmt.Sprintf("girdle: cannot load the credential for %s: %v", host, err))
			return
		}
		r.Header.Set("Authorization", header)
	}
	s.forwardAudited(w, r, host)
}

func (s *Server) plain(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.URL.Hostname())
	if _, ok := s.policy.Intercepted(host); ok {
		s.record(Event{Kind: "denied", Host: host, Method: r.Method, Path: r.URL.Path, Reason: "plain HTTP to an intercepted host"})
		deny(w, http.StatusForbidden, fmt.Sprintf("girdle: use https for %s", host))
		return
	}
	if port := r.URL.Port(); port != "" && port != "80" {
		s.record(Event{Kind: "denied", Host: host, Port: port, Reason: "only port 80 is proxied for plain HTTP"})
		deny(w, http.StatusForbidden, fmt.Sprintf("girdle: port %s is not allowed", port))
		return
	}
	if !s.policy.AllowsHostFor(host, IdentityFrom(r.Context()).Exe) {
		s.record(Event{Kind: "denied", Host: host, Exe: IdentityFrom(r.Context()).Exe, Reason: s.hostReason(host)})
		s.denyHost(w, host)
		return
	}
	s.firstSeen(host, "http")
	r.Header.Del("Proxy-Authorization")
	s.forward(w, r, "http", r.URL.Host)
}

func (s *Server) forwardAudited(w http.ResponseWriter, r *http.Request, host string) {
	exe := IdentityFrom(r.Context()).Exe
	s.forwardWith(w, r, "https", host, func(resp *http.Response) error {
		s.record(Event{Kind: "request", Host: host, Method: r.Method, Path: r.URL.Path, Exe: exe, Status: resp.StatusCode})
		return nil
	})
}

func (s *Server) forward(w http.ResponseWriter, r *http.Request, scheme, host string) {
	s.forwardWith(w, r, scheme, host, nil)
}

func (s *Server) forwardWith(w http.ResponseWriter, r *http.Request, scheme, host string, onResponse func(*http.Response) error) {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = scheme
			pr.Out.URL.Host = host
			pr.Out.Host = host
			pr.Out.Header.Del("Proxy-Authorization")
			pr.Out.Header.Del("Proxy-Connection")
		},
		Transport:      s.transport,
		FlushInterval:  -1,
		ModifyResponse: onResponse,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.record(Event{Kind: "error", Host: host, Method: r.Method, Path: r.URL.Path, Reason: err.Error()})
			deny(w, http.StatusBadGateway, fmt.Sprintf("girdle: upstream %s failed: %v", host, err))
		},
	}
	rp.ServeHTTP(noCloseNotify{w}, r.WithContext(context.WithoutCancel(r.Context())))
}

type noCloseNotify struct{ http.ResponseWriter }

func (w noCloseNotify) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) authorization(ctx context.Context, c profile.Credential) (string, error) {
	v, err := s.secrets.Get(ctx, c.Secret)
	if err != nil {
		return "", err
	}
	token := string(v.Reveal())
	switch c.Scheme {
	case profile.SchemeBasic:
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+token)), nil
	case profile.SchemeToken:
		return "token " + token, nil
	default:
		return "Bearer " + token, nil
	}
}

func scope(r profile.Rule, matched bool, method, path, host string, body []byte) string {
	if !matched {
		s := fmt.Sprintf("http %s %s %s", method, host, path)
		if gql := profile.DescribeGraphQL(body); gql != "" {
			s += " graphql " + gql
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
	if repo := repoPrefix(path); repo != "" {
		s += " in " + repo
	}
	return s
}

func repoPrefix(p string) string {
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	switch {
	case len(segs) >= 3 && strings.EqualFold(segs[0], "repos"):
		return strings.ToLower("/" + strings.Join(segs[:3], "/"))
	case len(segs) >= 2 && strings.EqualFold(segs[0], "repositories"):
		return strings.ToLower("/" + strings.Join(segs[:2], "/"))
	}
	return ""
}

const excerptLimit = 400

func bodyExcerpt(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	text := string(body)
	var gql struct {
		Query string `json:"query"`
	}
	if json.Unmarshal(body, &gql) == nil && gql.Query != "" {
		text = gql.Query
	}
	if len(text) > excerptLimit {
		text = text[:excerptLimit] + "…"
	}
	return "\n" + text
}

const maxInspectedBody = 1 << 20

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
	s.mu.Lock()
	key := "withheld " + host + " " + exe
	first := !s.seen[key]
	s.seen[key] = true
	s.mu.Unlock()
	if first {
		s.record(Event{Kind: "credential-withheld", Host: host, Reason: "not allowed for " + exe})
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
	w.Header().Set("X-Girdle-Denied", "1")
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

func canonicalPath(u *url.URL) bool {
	raw := strings.ToLower(u.EscapedPath())
	if strings.Contains(raw, "%2f") || strings.Contains(raw, "%5c") || strings.Contains(u.Path, "\\") || strings.Contains(u.Path, ";") {
		return false
	}
	p := u.Path
	if p == "" || p == "/" {
		return true
	}
	clean := path.Clean(p)
	return p == clean || p == clean+"/"
}

func identityEncoding(enc string) bool {
	enc = strings.TrimSpace(strings.ToLower(enc))
	return enc == "" || enc == "identity"
}

func (s *Server) hostReason(host string) string {
	if progs := s.policy.ProgramsFor(host); len(progs) > 0 {
		return "host allowed only for " + strings.Join(progs, ", ")
	}
	return "host not in the profile"
}

func (s *Server) denyHost(w http.ResponseWriter, host string) {
	if progs := s.policy.ProgramsFor(host); len(progs) > 0 {
		deny(w, http.StatusForbidden, fmt.Sprintf("girdle: profile %q lets only %s reach %s", s.cfg.Profile, strings.Join(progs, ", "), host))
		return
	}
	deny(w, http.StatusForbidden, fmt.Sprintf("girdle: %s is not in profile %q; add it to [egress] allow if the agent needs it", host, s.cfg.Profile))
}
