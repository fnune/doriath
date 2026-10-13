package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fnune/girdle/internal/approval"
	"github.com/fnune/girdle/internal/ca"
	"github.com/fnune/girdle/internal/profile"
	"github.com/fnune/girdle/internal/secret"
)

type upstream struct {
	mu       sync.Mutex
	requests []*http.Request
	bodies   [][]byte
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.requests = append(u.requests, r)
	u.bodies = append(u.bodies, body)
	u.mu.Unlock()
	fmt.Fprintf(w, "ok %s %s %d", r.Host, r.URL.Path, len(body))
}

func (u *upstream) last(t *testing.T) (*http.Request, []byte) {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.requests) == 0 {
		t.Fatal("upstream saw no request")
	}
	return u.requests[len(u.requests)-1], u.bodies[len(u.bodies)-1]
}

func (u *upstream) find(t *testing.T, path string) *http.Request {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, r := range u.requests {
		if r.URL.Path == path {
			return r
		}
	}
	t.Fatalf("upstream saw no request for %s", path)
	return nil
}

func (u *upstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.requests)
}

// redirectDialer sends every connection to one local address, whatever host
// the proxy asked for.
type redirectDialer struct{ tlsAddr, plainAddr string }

func (d redirectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	target := d.tlsAddr
	if strings.HasSuffix(address, ":80") {
		target = d.plainAddr
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, target)
}

type fakeApprover struct {
	mu       sync.Mutex
	verdict  approval.Verdict
	requests []approval.Request
}

func (a *fakeApprover) Submit(_ context.Context, req approval.Request, _ time.Duration) (approval.Decision, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requests = append(a.requests, req)
	reason := ""
	if a.verdict == approval.VerdictDeny {
		reason = "not today"
	}
	return approval.Decision{Verdict: a.verdict, Lasting: approval.LastingOnce, Reason: reason}, nil
}

type mapSecrets map[string]string

func (m mapSecrets) Get(_ context.Context, name string) (secret.Value, error) {
	v, ok := m[name]
	if !ok {
		return secret.Value{}, fmt.Errorf("secret %q: %w", name, secret.ErrUnknown)
	}
	return secret.NewValue([]byte(v)), nil
}

type events struct {
	mu   sync.Mutex
	list []Event
}

func (e *events) Egress(ev Event) {
	e.mu.Lock()
	e.list = append(e.list, ev)
	e.mu.Unlock()
}

func (e *events) has(kind, host string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ev := range e.list {
		if ev.Kind == kind && ev.Host == host {
			return true
		}
	}
	return false
}

type harness struct {
	dialAddrs redirectDialer
	proxyURL  *url.URL
	session   *ca.Authority
	upstream  *upstream
	upCA      *ca.Authority
	approver  *fakeApprover
	events    *events
}

const testProfile = `
secrets = { github = "github-test" }

[egress]
allow = ["example.com", "plain.example"]

[[http]]
host = "api.github.com"
credential = { secret = "github", scheme = "bearer" }

[[http.rules]]
method = "PUT"
path = "/repos/*/*/pulls/*/merge"
action = "deny"

[[http.rules]]
method = "POST"
path = "/repos/*/*/releases"
action = "approve"
summary = "Create a GitHub release"

[[http.rules]]
method = "POST"
path = "/graphql"
body_contains = ["mergePullRequest"]
action = "deny"

[[http]]
host = "github.com"
credential = { secret = "github", scheme = "basic", username = "x-access-token" }
`

func loadPolicy(t *testing.T) *profile.Profile {
	t.Helper()
	l := &profile.Loader{Profiles: mapFS{"t.toml": testProfile}, Home: "/home/u"}
	p, err := l.Load("t")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	up := &upstream{}
	upCA, err := ca.New([]string{"api.github.com", "github.com", "example.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewUnstartedServer(up)
	tlsServer.TLS = &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return upCA.Certificate(h.ServerName)
	}}
	tlsServer.StartTLS()
	t.Cleanup(tlsServer.Close)
	plainServer := httptest.NewServer(up)
	t.Cleanup(plainServer.Close)

	session, err := ca.New([]string{"api.github.com", "github.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	approver := &fakeApprover{verdict: approval.VerdictAllow}
	ev := &events{}
	srv := New(
		Config{Session: "s1", Profile: "t", ApprovalTTL: time.Second, UpstreamRoots: upCA.Pool()},
		loadPolicy(t),
		approver,
		mapSecrets{"github-test": "real-token"},
		session,
		redirectDialer{tlsAddr: tlsServer.Listener.Addr().String(), plainAddr: plainServer.Listener.Addr().String()},
		ev,
	)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() { _ = srv.Serve(l) }()
	u, _ := url.Parse("http://" + l.Addr().String())
	return &harness{dialAddrs: redirectDialer{tlsAddr: tlsServer.Listener.Addr().String(), plainAddr: plainServer.Listener.Addr().String()}, proxyURL: u, session: session, upstream: up, upCA: upCA, approver: approver, events: ev}
}

// client trusts both the session CA (for intercepted hosts) and the upstream
// CA (for tunneled hosts), as the jail's combined bundle does.
func (h *harness) client() *http.Client {
	pool := h.upCA.Pool()
	pool.AppendCertsFromPEM(h.session.CertPEM())
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(h.proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
		Timeout: 10 * time.Second,
	}
}

func (h *harness) dialer() redirectDialer { return h.dialAddrs }

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestInterceptInjectsCredential(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "token placeholder")
	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body(t, resp))
	}
	got, _ := h.upstream.last(t)
	if got.Header.Get("Authorization") != "Bearer real-token" {
		t.Fatalf("upstream Authorization = %q", got.Header.Get("Authorization"))
	}
	if _, err := resp.TLS.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: "api.github.com", Roots: h.session.Pool()}); err != nil {
		t.Fatal("intercepted host must present the session CA's leaf")
	}
	if !h.events.has("intercept", "api.github.com") {
		t.Fatal("first intercept not recorded")
	}
}

func TestBasicCredentialForGit(t *testing.T) {
	h := newHarness(t)
	payload := bytes.Repeat([]byte("pack"), 2<<20)
	resp, err := h.client().Post("https://github.com/fnune/project.git/git-receive-pack", "application/x-git-receive-pack-request", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != http.StatusOK || !strings.HasSuffix(b, fmt.Sprint(len(payload))) {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	got, gotBody := h.upstream.last(t)
	if got.Header.Get("Authorization") != "Basic eC1hY2Nlc3MtdG9rZW46cmVhbC10b2tlbg==" {
		t.Fatalf("upstream Authorization = %q", got.Header.Get("Authorization"))
	}
	if len(gotBody) != len(payload) {
		t.Fatalf("upstream got %d bytes, want %d", len(gotBody), len(payload))
	}
}

func TestRuleDeny(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(http.MethodPut, "https://api.github.com/repos/fnune/project/pulls/3/merge", nil)
	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b := body(t, resp)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Girdle-Denied") != "1" {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var msg struct{ Message string }
	if err := json.Unmarshal([]byte(b), &msg); err != nil || !strings.Contains(msg.Message, "not allowed") {
		t.Fatalf("body %q", b)
	}
	if h.upstream.count() != 0 {
		t.Fatal("a denied request must not reach upstream")
	}
}

func TestRuleApprove(t *testing.T) {
	h := newHarness(t)
	post := func() *http.Response {
		resp, err := h.client().Post("https://api.github.com/repos/fnune/project/releases", "application/json", strings.NewReader(`{"tag_name":"v1"}`))
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	if resp := post(); resp.StatusCode != http.StatusOK {
		t.Fatalf("approved: status %d: %s", resp.StatusCode, body(t, resp))
	}
	h.approver.mu.Lock()
	req := h.approver.requests[0]
	h.approver.verdict = approval.VerdictDeny
	h.approver.mu.Unlock()
	if req.Summary != "Create a GitHub release" || req.Scope != "http POST api.github.com /repos/*/*/releases" || req.Session != "s1" {
		t.Fatalf("approval request = %+v", req)
	}
	resp := post()
	if b := body(t, resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(b, "Create a GitHub release was denied: not today") {
		t.Fatalf("denied: status %d: %s", resp.StatusCode, b)
	}
	if h.upstream.count() != 1 {
		t.Fatalf("upstream count = %d, want 1", h.upstream.count())
	}
}

func TestTunnelPassesThrough(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/x", nil)
	req.Header.Set("Authorization", "mine")
	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if _, err := resp.TLS.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: "example.com", Roots: h.session.Pool()}); err == nil {
		t.Fatal("a tunneled host must show the upstream certificate, not a session leaf")
	}
	got, _ := h.upstream.last(t)
	if got.Header.Get("Authorization") != "mine" {
		t.Fatal("tunnels must not touch headers")
	}
	if !h.events.has("tunnel", "example.com") {
		t.Fatal("tunnel not recorded")
	}
}

func TestDeniedHostAndPort(t *testing.T) {
	h := newHarness(t)
	for _, target := range []string{"evil.example:443", "example.com:8443"} {
		conn, err := net.Dial("tcp", h.proxyURL.Host)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status %d", target, resp.StatusCode)
		}
		_ = conn.Close()
	}
	if !h.events.has("denied", "evil.example") {
		t.Fatal("denied host not recorded")
	}
}

func TestHostHeaderMustMatchTunnel(t *testing.T) {
	h := newHarness(t)
	conn, err := net.Dial("tcp", h.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	tc := tls.Client(conn, &tls.Config{ServerName: "api.github.com", RootCAs: h.session.Pool()})
	fmt.Fprint(tc, "GET /user HTTP/1.1\r\nHost: evil.example\r\n\r\n")
	resp, err = http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if h.upstream.count() != 0 {
		t.Fatal("misdirected request reached upstream")
	}
}

func TestSNIMustMatchTunnel(t *testing.T) {
	h := newHarness(t)
	conn, err := net.Dial("tcp", h.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n")
	if _, err := http.ReadResponse(bufio.NewReader(conn), nil); err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(conn, &tls.Config{ServerName: "github.com", RootCAs: h.session.Pool()})
	if err := tc.Handshake(); err == nil {
		t.Fatal("handshake with a different SNI must fail")
	}
}

func TestPlainHTTP(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	resp, err := c.Get("http://plain.example/a")
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != http.StatusOK || !strings.HasPrefix(b, "ok plain.example /a") {
		t.Fatalf("allowed: %d %s", resp.StatusCode, b)
	}
	for _, u := range []string{"http://evil.example/", "http://api.github.com/user", "http://plain.example:8080/"} {
		resp, err := c.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status %d", u, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestMissingSecretFailsClosed(t *testing.T) {
	h := newHarness(t)
	p := loadPolicy(t)
	p.Secrets["github"] = "absent"
	srv := New(Config{Profile: "t", ApprovalTTL: time.Second, UpstreamRoots: h.upCA.Pool()}, p, h.approver, mapSecrets{}, h.session, redirectDialer{}, h.events)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	host, _ := p.Intercepted("api.github.com")
	srv.intercepted(rec, req, "api.github.com", host)
	if rec.Code != http.StatusBadGateway || h.upstream.count() != 0 {
		t.Fatalf("status %d, upstream %d", rec.Code, h.upstream.count())
	}
}

func TestGraphQLBodyRule(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	resp, err := c.Post("https://api.github.com/graphql", "application/json", strings.NewReader(`{"query":"mutation{mergePullRequest(input:{pullRequestId:\"x\"}){clientMutationId}}"}`))
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("merge mutation: %d %s", resp.StatusCode, b)
	}
	resp, err = c.Post("https://api.github.com/graphql", "application/json", strings.NewReader(`{"query":"{viewer{login}}"}`))
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != http.StatusOK || !strings.Contains(b, "/graphql 27") {
		t.Fatalf("read query: %d %s", resp.StatusCode, b)
	}
	_, upBody := h.upstream.last(t)
	if string(upBody) != `{"query":"{viewer{login}}"}` {
		t.Fatalf("inspected body must still reach upstream intact: %q", upBody)
	}
	big := strings.Repeat("a", maxInspectedBody+10)
	resp, err = c.Post("https://api.github.com/graphql", "application/json", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	if body(t, resp); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d", resp.StatusCode)
	}
}

func TestAbsoluteHTTPSRequests(t *testing.T) {
	h := newHarness(t)
	send := func(rawURL string, header string) *http.Response {
		t.Helper()
		conn, err := net.Dial("tcp", h.proxyURL.Host)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		u, _ := url.Parse(rawURL)
		fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\n%sConnection: close\r\n\r\n", rawURL, u.Host, header)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	if resp := send("https://example.com/abs", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("allowed: %d", resp.StatusCode)
	}
	if resp := send("https://evil.example/", ""); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied host: %d", resp.StatusCode)
	}
	if resp := send("https://api.github.com/user", "Authorization: token x\r\n"); resp.StatusCode != http.StatusOK {
		t.Fatalf("intercepted: %d", resp.StatusCode)
	}
	got := h.upstream.find(t, "/user")
	if got.Header.Get("Authorization") != "Bearer real-token" {
		t.Fatalf("credential not injected: %q", got.Header.Get("Authorization"))
	}
	resp := send("https://api.github.com/repos/a/b/pulls/1/merge", "")
	if resp.Request = nil; resp.StatusCode != http.StatusOK {
		t.Fatalf("GET on a PUT-only rule must pass: %d", resp.StatusCode)
	}
}

func TestHalfCloseStillGetsResponse(t *testing.T) {
	h := newHarness(t)
	conn, err := net.Dial("tcp", h.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "GET https://example.com/half HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_ = conn.(*net.TCPConn).CloseWrite()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != http.StatusOK || !strings.Contains(b, "/half") {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
}

func TestCredentialOnlyForListedBinaries(t *testing.T) {
	h := newHarness(t)
	p := loadPolicy(t)
	for i := range p.HTTP {
		if p.HTTP[i].Credential != nil {
			p.HTTP[i].Credential.Binaries = []string{"gh"}
		}
	}
	srv := New(Config{Profile: "t", ApprovalTTL: time.Second, UpstreamRoots: h.upCA.Pool()}, p, h.approver, mapSecrets{"github-test": "real-token"}, h.session, h.dialer(), h.events)
	host, _ := p.Intercepted("api.github.com")
	call := func(exe string) *http.Request {
		t.Helper()
		before := h.upstream.count()
		req := httptest.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
		req = req.WithContext(withIdentity(req.Context(), Identity{PID: 9, Exe: exe}))
		rec := httptest.NewRecorder()
		srv.intercepted(rec, req, "api.github.com", host)
		if rec.Code != http.StatusOK || h.upstream.count() != before+1 {
			t.Fatalf("%s: status %d", exe, rec.Code)
		}
		got, _ := h.upstream.last(t)
		return got
	}
	if got := call("/nix/store/abc-gh/bin/gh"); got.Header.Get("Authorization") != "Bearer real-token" {
		t.Errorf("gh must get the credential, got %q", got.Header.Get("Authorization"))
	}
	if got := call("/nix/store/abc-curl/bin/curl"); got.Header.Get("Authorization") != "" {
		t.Errorf("curl must go without the credential, got %q", got.Header.Get("Authorization"))
	}
	if !h.events.has("credential-withheld", "api.github.com") {
		t.Error("withholding must be recorded")
	}
}

type fakePeers struct {
	trusted int
	exe     string
}

func (f fakePeers) TrustsHeader(pid int) bool { return pid == f.trusted }
func (f fakePeers) Exe(int) string            { return f.exe }

func TestIdentifyingListener(t *testing.T) {
	for name, tc := range map[string]struct {
		trust   bool
		send    string
		wantExe string
		closed  bool
	}{
		"header from init":     {trust: true, send: "GIRDLE-PEER {\"pid\":5,\"exe\":\"/nix/store/x-gh/bin/gh\"}\nGET / HTTP/1.1\r\n", wantExe: "/nix/store/x-gh/bin/gh"},
		"header from stranger": {trust: false, send: "GIRDLE-PEER {\"pid\":5,\"exe\":\"/nix/store/x-gh/bin/gh\"}\n", wantExe: "/usr/bin/self"},
		"init without header":  {trust: true, send: "GET / HTTP/1.1\r\n", closed: true},
	} {
		t.Run(name, func(t *testing.T) {
			sock := filepath.Join(t.TempDir(), "p.sock")
			raw, err := net.Listen("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			trusted := -1
			if tc.trust {
				trusted = os.Getpid()
			}
			l := &IdentifyingListener{Listener: raw, Peers: fakePeers{trusted: trusted, exe: "/usr/bin/self"}}
			c, err := net.Dial("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			fmt.Fprint(c, tc.send)
			got, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer got.Close()
			if tc.closed {
				if _, err := got.Read(make([]byte, 1)); err == nil {
					t.Fatal("a missing header must end the connection")
				}
				return
			}
			if id := connIdentity(got); id.Exe != tc.wantExe {
				t.Fatalf("identity = %+v", id)
			}
			if tc.trust {
				line, _ := bufio.NewReader(got).ReadString('\n')
				if line != "GET / HTTP/1.1\r\n" {
					t.Fatalf("bytes after the header = %q", line)
				}
			}
		})
	}
}

func TestCanonicalPath(t *testing.T) {
	for raw, want := range map[string]bool{
		"/repos/a/b/pulls/1/merge":      true,
		"/repos/a/b/":                   true,
		"/":                             true,
		"/repos/a/b//pulls/1/merge":     false,
		"/repos/a/b/./pulls/1/merge":    false,
		"/repos/a/x/../b/pulls/1/merge": false,
		"/repos/a%2Fb/pulls/1/merge":    false,
	} {
		u, err := url.Parse("https://api.github.com" + raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := canonicalPath(u); got != want {
			t.Errorf("canonicalPath(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestEscapedMutationIsCaught(t *testing.T) {
	h := newHarness(t)
	resp, err := h.client().Post("https://api.github.com/graphql", "application/json", strings.NewReader(`{"query":"mutation{merge\u0050ullRequest(input:{}){clientMutationId}}"}`))
	if err != nil {
		t.Fatal(err)
	}
	if body(t, resp); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("an escaped mutation name got through: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodPut, "https://api.github.com/repos/a/b//pulls/1/merge", nil)
	resp, err = h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if body(t, resp); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a doubled slash got through: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodPut, "https://api.github.com/REPOS/a/b/PULLS/1/MERGE", nil)
	resp, err = h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if body(t, resp); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a different case got past the rule: %d", resp.StatusCode)
	}
}
