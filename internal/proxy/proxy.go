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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fnune/girdle/internal/approval"
	"github.com/fnune/girdle/internal/profile"
	"github.com/fnune/girdle/internal/secret"
)

type Policy interface {
	AllowsHost(host string) bool
	Intercepted(host string) (profile.HTTPHost, bool)
	SecretName(name string) string
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
	Port   string `json:"port,omitempty"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	Action string `json:"action,omitempty"`
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
	srv := &http.Server{Handler: http.HandlerFunc(s.handle), ReadHeaderTimeout: 30 * time.Second}
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

// absoluteHTTPS serves clients that send "GET https://host/path" to the
// proxy instead of a CONNECT, as busybox wget does. The proxy makes the TLS
// connection itself, so the same rules apply as for a tunnel.
func (s *Server) absoluteHTTPS(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.URL.Hostname())
	if port := r.URL.Port(); port != "" && port != "443" {
		s.record(Event{Kind: "denied", Host: host, Port: port, Reason: "only port 443 is proxied for HTTPS"})
		deny(w, http.StatusForbidden, fmt.Sprintf("girdle: port %s is not allowed", port))
		return
	}
	if !s.policy.AllowsHost(host) {
		s.record(Event{Kind: "denied", Host: host, Reason: "host not in the profile"})
		deny(w, http.StatusForbidden, fmt.Sprintf("girdle: %s is not in profile %q; add it to [egress] allow if the agent needs it", host, s.cfg.Profile))
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
	if !s.policy.AllowsHost(host) {
		s.record(Event{Kind: "denied", Host: host, Port: port, Reason: "host not in the profile"})
		deny(w, http.StatusForbidden, fmt.Sprintf("girdle: %s is not in profile %q; add it to [egress] allow if the agent needs it", host, s.cfg.Profile))
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
		s.intercept(prefixed(conn, buf.Reader), host, intercept)
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
	s.firstSeen(host, "tunnel")
	pipe(prefixed(conn, buf.Reader), upstream)
}

// intercept serves HTTP on the decrypted connection, one request at a time.
func (s *Server) intercept(conn net.Conn, host string, rules profile.HTTPHost) {
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
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 30 * time.Second}
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
	var body []byte
	if rules.NeedsBody(r.Method, r.URL.Path) {
		var tooLarge bool
		var err error
		body, tooLarge, err = readBody(r, maxInspectedBody)
		if err != nil {
			deny(w, http.StatusBadRequest, "girdle: cannot read the request body")
			return
		}
		if tooLarge {
			// Refused rather than passed through, so that padding cannot
			// hide a mutation from a rule.
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
			Details: fmt.Sprintf("%s https://%s%s", r.Method, host, r.URL.RequestURI()),
			Scope:   scope(rule, matched, r.Method, r.URL.Path, host),
		}, s.cfg.ApprovalTTL)
		if err != nil || d.Verdict != approval.VerdictAllow {
			reason := "denied"
			if d.Verdict == approval.VerdictNone {
				reason = "nobody approved it in time"
			}
			s.record(Event{Kind: "denied", Host: host, Method: r.Method, Path: r.URL.Path, Action: string(action), Reason: reason})
			deny(w, http.StatusForbidden, fmt.Sprintf("girdle: %s was %s", summary, reason))
			return
		}
		s.record(Event{Kind: "approved", Host: host, Method: r.Method, Path: r.URL.Path, Reason: summary})
	}

	if c := rules.Credential; c != nil {
		header, err := s.authorization(r.Context(), *c)
		if err != nil {
			s.record(Event{Kind: "error", Host: host, Method: r.Method, Path: r.URL.Path, Reason: err.Error()})
			deny(w, http.StatusBadGateway, fmt.Sprintf("girdle: cannot load the credential for %s: %v", host, err))
			return
		}
		r.Header.Set("Authorization", header)
	}
	s.forward(w, r, "https", host)
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
	if !s.policy.AllowsHost(host) {
		s.record(Event{Kind: "denied", Host: host, Reason: "host not in the profile"})
		deny(w, http.StatusForbidden, fmt.Sprintf("girdle: %s is not in profile %q; add it to [egress] allow if the agent needs it", host, s.cfg.Profile))
		return
	}
	s.firstSeen(host, "http")
	r.Header.Del("Proxy-Authorization")
	s.forward(w, r, "http", r.URL.Host)
}

func (s *Server) forward(w http.ResponseWriter, r *http.Request, scheme, host string) {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = scheme
			pr.Out.URL.Host = host
			pr.Out.Host = host
			pr.Out.Header.Del("Proxy-Authorization")
			pr.Out.Header.Del("Proxy-Connection")
		},
		Transport:     s.transport,
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.record(Event{Kind: "error", Host: host, Method: r.Method, Path: r.URL.Path, Reason: err.Error()})
			deny(w, http.StatusBadGateway, fmt.Sprintf("girdle: upstream %s failed: %v", host, err))
		},
	}
	// Some clients half-close their side after sending the request, which
	// net/http reports as a cancelled context. The response is still wanted,
	// so the upstream request must outlive that signal.
	rp.ServeHTTP(noCloseNotify{w}, r.WithContext(context.WithoutCancel(r.Context())))
}

// noCloseNotify hides http.CloseNotifier, which ReverseProxy would otherwise
// use to cancel the upstream request on a half-close. Unwrap keeps flushing
// and hijacking reachable through http.ResponseController.
type noCloseNotify struct{ http.ResponseWriter }

func (w noCloseNotify) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) authorization(ctx context.Context, c profile.Credential) (string, error) {
	v, err := s.secrets.Get(ctx, s.policy.SecretName(c.Secret))
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

// scope identifies what an approval covers. Requests that match the same rule
// share a scope, so "allow for this session" covers them all.
func scope(r profile.Rule, matched bool, method, path, host string) string {
	if !matched {
		return fmt.Sprintf("http %s %s %s", method, host, path)
	}
	s := fmt.Sprintf("http %s %s %s", r.Method, host, string(r.Path))
	if len(r.BodyContains) > 0 {
		s += " " + strings.Join(r.BodyContains, ",")
	}
	return s
}

const maxInspectedBody = 1 << 20

// readBody reads up to limit bytes and puts the body back for forwarding.
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
