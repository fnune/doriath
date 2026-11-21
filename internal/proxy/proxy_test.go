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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/ca"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/secret"
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
	w.Header().Set("X-Upstream-Proto", r.Proto)
	if r.Header.Get("Content-Type") == "application/grpc" {
		w.Header().Set("Trailer", "Grpc-Status")
		defer w.Header().Set("Grpc-Status", "0")
	}
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
	err      error
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
	return approval.Decision{Verdict: a.verdict, Lasting: approval.LastingOnce, Reason: reason}, a.err
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
[secrets.github]
keyring = true

[egress]
allow = ["example.com", "plain.example"]

[[http]]
host = "api.github.com"
repositories = ["/repos/*/*"]
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

[[http.rules]]
method = "POST"
path = "/graphql"
graphql = { operation = "query" }
action = "allow"

[[http.rules]]
method = "POST"
path = "/graphql"
graphql = { operation = "mutation", fields = ["createRef"] }
action = "approve"
summary = "Create a ref"

[[http]]
host = "github.com"
credential = { secret = "github", scheme = "basic", username = "x-access-token" }
`

func loadPolicy(t *testing.T) *profile.Profile {
	t.Helper()
	return loadProfile(t, testProfile)
}

func loadProfile(t *testing.T, toml string) *profile.Profile {
	t.Helper()
	l := &profile.Loader{Profiles: mapFS{"t.toml": toml}, Home: "/home/u"}
	p, err := l.Load("t")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWith(t, testProfile)
}

func newHarnessWith(t *testing.T, toml string) *harness {
	t.Helper()
	return newHarnessFor(t, loadProfile(t, toml))
}

func newHarnessFor(t *testing.T, p *profile.Profile) *harness {
	t.Helper()
	up := &upstream{}
	return newHarnessServing(t, p, up, up)
}

// newHarnessServing starts the proxy in front of a TLS server that runs
// handler. up is what the tests read back, and stays empty if handler is not it.
func newHarnessServing(t *testing.T, p *profile.Profile, up *upstream, handler http.Handler) *harness {
	t.Helper()
	return newHarnessWithSecrets(t, p, up, handler, mapSecrets{"github": "real-token", "claude": "real-login", "aws": `{"Version":1,"AccessKeyId":"AKIAREALKEY","SecretAccessKey":"real-secret","SessionToken":"real-session","Expiration":"2099-01-01T00:00:00Z"}`})
}

func newHarnessWithSecrets(t *testing.T, p *profile.Profile, up *upstream, handler http.Handler, secrets Secrets) *harness {
	t.Helper()
	upCA, err := ca.New([]string{"api.github.com", "github.com", "example.com", "mcp.example.com", "bridge.example.com", "sts.us-east-1.amazonaws.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewUnstartedServer(handler)
	tlsServer.TLS = &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return upCA.Certificate(h.ServerName)
	}}
	tlsServer.EnableHTTP2 = true
	tlsServer.StartTLS()
	t.Cleanup(tlsServer.Close)
	plainServer := httptest.NewServer(up)
	t.Cleanup(plainServer.Close)

	session, err := ca.New([]string{"api.github.com", "github.com", "mcp.example.com", "bridge.example.com", "sts.us-east-1.amazonaws.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	approver := &fakeApprover{verdict: approval.VerdictAllow}
	ev := &events{}
	srv := New(
		Config{Session: "s1", Profile: "t", ApprovalTTL: time.Second, UpstreamRoots: upCA.Pool()},
		p,
		approver,
		secrets,
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
	if !h.events.has("request", "api.github.com") {
		t.Fatal("each credentialed request must be recorded")
	}
}

func TestBasicCredentialForGit(t *testing.T) {
	h := newHarness(t)
	payload := bytes.Repeat([]byte("pack"), 2<<20)
	resp, err := h.client().Post("https://github.com/acme/app.git/git-receive-pack", "application/x-git-receive-pack-request", bytes.NewReader(payload))
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
	req, _ := http.NewRequest(http.MethodPut, "https://api.github.com/repos/acme/app/pulls/3/merge", nil)
	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b := body(t, resp)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Doriath-Denied") != "1" {
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

func TestGitHostScopeNamesTheRepository(t *testing.T) {
	push := profile.Rule{Method: "POST", Path: "/**/git-receive-pack", Action: profile.ActionApprove}
	var forge profile.HTTPHost
	at := func(path string) string {
		return scope(push, true, "POST", path, "github.com", nil, nil, forge.Repository(path), "")
	}
	a := at("/acme/app.git/git-receive-pack")
	if a != "http POST github.com /**/git-receive-pack in /acme/app" {
		t.Fatalf("scope = %q", a)
	}
	if b := at("/acme/App/git-receive-pack"); b != a {
		t.Errorf("the same repository with and without .git must share a grant: %q", b)
	}
	if c := at("/acme/other/git-receive-pack"); c == a {
		t.Error("a push grant for one repository must not answer a push to another")
	}
	if e := at("/acme/app.git/git-receive-pack/"); e != a {
		t.Errorf("a trailing slash must keep the repository in the scope: %q", e)
	}
	if d := at("/group/sub/proj.git/git-receive-pack"); !strings.HasSuffix(d, " in /group/sub/proj") {
		t.Errorf("a repository in a subgroup must be named whole: %q", d)
	}
}

func TestAnEncodedPathCannotSpellAnotherRulesScope(t *testing.T) {
	release := profile.Rule{Method: "POST", Path: "/repos/*/*/releases", Action: profile.ActionApprove}
	real := scope(release, true, "POST", "/repos/o/r/releases", "api.github.com", nil, nil, "/repos/o/r", "")
	forged := scope(profile.Rule{}, false, "POST", "/repos/*/*/releases in /repos/o/r", "api.github.com", nil, nil, "", "")
	if real == forged {
		t.Errorf("a request off the rules shares the release scope: %q", forged)
	}
	tools := profile.Rule{Method: "POST", Path: "/**", MCPTools: []string{"*"}, Action: profile.ActionApprove}
	call := func(tool string) []byte {
		return []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `"}}`)
	}
	if scope(tools, true, "POST", "/mcp", "h", call("t in /o/r"), nil, "", "") == scope(tools, true, "POST", "/o/r/mcp", "h", call("t"), nil, "/o/r", "") {
		t.Error("a tool name spells a repository in the scope")
	}
}

func TestAPIScopeComesFromTheHostsRepositories(t *testing.T) {
	merge := profile.Rule{Method: "PUT", Path: "/api/v4/projects/*/merge_requests/*/merge", Action: profile.ActionApprove}
	pattern, err := profile.ParsePathPattern("/api/v4/projects/*")
	if err != nil {
		t.Fatal(err)
	}
	gitlab := profile.HTTPHost{Repositories: []profile.PathPattern{pattern}}
	path := "/api/v4/projects/42/merge_requests/7/merge"
	if s := scope(merge, true, "PUT", path, "gitlab.com", nil, nil, gitlab.Repository(path), ""); !strings.HasSuffix(s, " in /api/v4/projects/42") {
		t.Errorf("scope = %q", s)
	}
	if s := scope(merge, true, "PUT", path, "gitlab.com", nil, nil, profile.HTTPHost{}.Repository(path), ""); strings.Contains(s, " in ") {
		t.Errorf("without repositories the API path names no repository: %q", s)
	}
}

func TestRuleApprove(t *testing.T) {
	h := newHarness(t)
	post := func() *http.Response {
		resp, err := h.client().Post("https://api.github.com/repos/acme/app/releases", "application/json", strings.NewReader(`{"tag_name":"v1"}`))
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
	if req.Summary != "Create a GitHub release in api.github.com/repos/acme/app" || req.Scope != "http POST api.github.com /repos/*/*/releases in /repos/acme/app" || req.Session != "s1" {
		t.Fatalf("approval request = %+v", req)
	}
	resp := post()
	if b := body(t, resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(b, "Create a GitHub release in api.github.com/repos/acme/app was denied: not today") {
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

func TestSNIMustMatchOpaqueTunnel(t *testing.T) {
	h := newHarness(t)
	conn, err := net.Dial("tcp", h.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	if _, err := http.ReadResponse(bufio.NewReader(conn), nil); err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(conn, &tls.Config{ServerName: "github.com", RootCAs: h.upCA.Pool()})
	if err := tc.Handshake(); err == nil {
		t.Fatal("a tunnel to example.com must not carry a handshake for github.com")
	}
	if !h.events.has("denied", "example.com") {
		t.Fatal("the mismatch was not recorded")
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

func TestAMissingSecretFailsClosedAndTellsTheAgentWhoFixesIt(t *testing.T) {
	h := newHarness(t)
	p := loadPolicy(t)
	srv := New(Config{Profile: "t", ApprovalTTL: time.Second, UpstreamRoots: h.upCA.Pool()}, p, h.approver, mapSecrets{}, h.session, redirectDialer{}, h.events)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	host, _ := p.Intercepted("api.github.com")
	srv.intercepted(rec, req, "api.github.com", "api.github.com", host)
	if rec.Code != http.StatusBadGateway || h.upstream.count() != 0 {
		t.Fatalf("status %d, upstream %d", rec.Code, h.upstream.count())
	}
	if msg := deniedMessage(t, rec); !strings.Contains(msg, "doriath tries again within 30 seconds") {
		t.Errorf("message = %q", msg)
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

func TestGraphQLOperationRule(t *testing.T) {
	h := newHarness(t)
	post := func(query string) {
		t.Helper()
		b, _ := json.Marshal(map[string]string{"query": query})
		resp, err := h.client().Post("https://api.github.com/graphql", "application/json", strings.NewReader(string(b)))
		if err != nil {
			t.Fatal(err)
		}
		if b := body(t, resp); resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %s", query, resp.StatusCode, b)
		}
	}
	post("query { viewer { login } }")
	post("mutation { createRef(input: {}) { clientMutationId } }")
	post("mutation { createCommitOnBranch(input: {}) { commit { oid } } }")
	h.approver.mu.Lock()
	defer h.approver.mu.Unlock()
	if len(h.approver.requests) != 2 {
		t.Fatalf("approval requests = %+v, want two: the query passes", h.approver.requests)
	}
	if r := h.approver.requests[0]; r.Summary != "Create a ref" || r.Scope != "http POST api.github.com /graphql graphql mutation createRef" {
		t.Errorf("named mutation: %+v", r)
	}
	if r := h.approver.requests[1]; r.Scope != "http POST api.github.com /graphql graphql mutation createCommitOnBranch" {
		t.Errorf("a session grant for an unnamed mutation must cover only that mutation: %+v", r)
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
	srv := New(Config{Profile: "t", ApprovalTTL: time.Second, UpstreamRoots: h.upCA.Pool()}, p, h.approver, mapSecrets{"github": "real-token"}, h.session, h.dialer(), h.events)
	host, _ := p.Intercepted("api.github.com")
	call := func(exe string) *http.Request {
		t.Helper()
		before := h.upstream.count()
		req := httptest.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
		req = req.WithContext(withIdentity(req.Context(), Identity{PID: 9, Exe: exe}))
		rec := httptest.NewRecorder()
		srv.intercepted(rec, req, "api.github.com", "api.github.com", host)
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

func (f fakePeers) TrustsHeader(pid int) bool  { return pid == f.trusted }
func (f fakePeers) Identify(pid int) Identity  { return Identity{PID: pid, Exe: f.exe} }
func (f fakePeers) Vouch(id Identity) Identity { return id }

func TestIdentifyingListener(t *testing.T) {
	for name, tc := range map[string]struct {
		trust   bool
		send    string
		wantExe string
		closed  bool
	}{
		"header from init":     {trust: true, send: "DORIATH-PEER {\"pid\":5,\"exe\":\"/nix/store/x-gh/bin/gh\"}\nGET / HTTP/1.1\r\n", wantExe: "/nix/store/x-gh/bin/gh"},
		"header from stranger": {trust: false, send: "DORIATH-PEER {\"pid\":5,\"exe\":\"/nix/store/x-gh/bin/gh\"}\n", wantExe: "/usr/bin/self"},
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
		"//":                            false,
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

func TestMethodCaseAndCompressedBodies(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(strings.ToLower(http.MethodPut), "https://api.github.com/repos/a/b/pulls/1/merge", nil)
	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if body(t, resp); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a lower-case method got through: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodPost, "https://api.github.com/graphql", strings.NewReader("compressed"))
	req.Header.Set("Content-Encoding", "gzip")
	resp, err = h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if body(t, resp); resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("a compressed inspected body got through: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodPut, "https://api.github.com/repos/a/b/pulls/1/merge/", nil)
	resp, err = h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if body(t, resp); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a trailing slash got past the rule: %d", resp.StatusCode)
	}
}

func pktLine(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

func TestParseRefCommands(t *testing.T) {
	old, next := strings.Repeat("a", 40), strings.Repeat("b", 40)
	data := pktLine(old+" "+next+" refs/heads/main\x00report-status side-band-64k\n") +
		pktLine(zeroID+" "+next+" refs/heads/feature/x\n") +
		pktLine(old+" "+zeroID+" refs/tags/v1\n") + "0000PACK..."
	got, unread := parseRefCommands([]byte(data))
	if len(got) != 3 || unread {
		t.Fatalf("got %+v", got)
	}
	shorts := []string{got[0].short(), got[1].short(), got[2].short()}
	if strings.Join(shorts, ", ") != "main, feature/x, delete tag v1" {
		t.Errorf("short names %q", shorts)
	}
	if got[0].line() != "update refs/heads/main aaaaaaaaaaaa..bbbbbbbbbbbb" || got[1].line() != "create refs/heads/feature/x at bbbbbbbbbbbb" || !strings.HasPrefix(got[2].line(), "delete refs/tags/v1") {
		t.Errorf("lines %q, %q, %q", got[0].line(), got[1].line(), got[2].line())
	}
	for _, junk := range []string{"", "zzzz", "0005x", "0010short\n", "PACK"} {
		if refs, _ := parseRefCommands([]byte(junk)); len(refs) != 0 {
			t.Errorf("%q gave %+v", junk, refs)
		}
	}
}

func TestAPushSaysWhichRefsItCouldNotRead(t *testing.T) {
	old, next := strings.Repeat("a", 40), strings.Repeat("b", 40)
	sha256 := strings.Repeat("c", 64)
	data := pktLine(old+" "+next+" HEAD\x00report-status\n") +
		pktLine(old+" "+next+" refs/heads/main\n") +
		pktLine(sha256+" "+strings.Repeat("d", 64)+" refs/heads/next\n") + "0000PACK..."
	got, unread := parseRefCommands([]byte(data))
	if len(got) != 2 || got[0].ref != "refs/heads/main" || got[1].ref != "refs/heads/next" || !unread {
		t.Errorf("got %+v, unread %v", got, unread)
	}
	if _, unread := parseRefCommands([]byte(pktLine(old + " " + next + " refs/heads/main\n"))); !unread {
		t.Error("commands cut off before the flush packet read as complete")
	}
	if _, unread := parseRefCommands([]byte(pktLine("shallow "+old+"\n") + pktLine(old+" "+next+" refs/heads/main\n") + "0000")); unread {
		t.Error("a push from a shallow clone has refs doriath could not read")
	}
}

func TestPushRequestNamesItsRefs(t *testing.T) {
	h := newHarnessWith(t, `
[secrets.github]
command = ["true"]

[[http]]
host = "github.com"
credential = { secret = "github", scheme = "basic", username = "x-access-token" }

[[http.rules]]
method = "POST"
path = "/**/git-receive-pack"
action = "approve"
summary = "Push"
`)
	old, next := strings.Repeat("a", 40), strings.Repeat("b", 40)
	payload := pktLine(old+" "+next+" refs/heads/main\x00report-status\n") + "0000" + strings.Repeat("P", 200<<10)
	resp, err := h.client().Post("https://github.com/group/sub/proj.git/git-receive-pack", "application/x-git-receive-pack-request", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	h.approver.mu.Lock()
	req := h.approver.requests[0]
	h.approver.mu.Unlock()
	if req.Summary != "Push in github.com/group/sub/proj: main" || !strings.Contains(req.Details, "update refs/heads/main aaaaaaaaaaaa..bbbbbbbbbbbb") || !strings.HasSuffix(req.Scope, " in /group/sub/proj") {
		t.Fatalf("approval request = %+v", req)
	}
	if _, got := h.upstream.last(t); string(got) != payload {
		t.Fatalf("the upstream got %d bytes of %d", len(got), len(payload))
	}
}

func TestAPushToAllowedRefsNeedsNoApproval(t *testing.T) {
	h := newHarnessWith(t, `
[secrets.github]
command = ["true"]

[[http]]
host = "github.com"
credential = { secret = "github", scheme = "basic", username = "x-access-token" }

[[http.rules]]
method = "POST"
path = "/**/git-receive-pack"
refs = ["refs/heads/agent/**"]
action = "allow"

[[http.rules]]
method = "POST"
path = "/**/git-receive-pack"
action = "approve"
summary = "Push"
`)
	old, next := strings.Repeat("a", 40), strings.Repeat("b", 40)
	push := func(refs []string, encoding string) {
		t.Helper()
		var payload string
		for i, ref := range refs {
			caps := ""
			if i == 0 {
				caps = "\x00report-status"
			}
			payload += pktLine(old + " " + next + " " + ref + caps + "\n")
		}
		payload += "0000" + strings.Repeat("P", 200<<10)
		req, _ := http.NewRequest(http.MethodPost, "https://github.com/o/r.git/git-receive-pack", strings.NewReader(payload))
		if encoding != "" {
			req.Header.Set("Content-Encoding", encoding)
		}
		resp, err := h.client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if b := body(t, resp); resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d: %s", resp.StatusCode, b)
		}
	}
	approvals := func() []approval.Request {
		h.approver.mu.Lock()
		defer h.approver.mu.Unlock()
		return slices.Clone(h.approver.requests)
	}

	push([]string{"refs/heads/agent/fix"}, "")
	if got := approvals(); len(got) != 0 {
		t.Fatalf("a push to an agent branch waited for an answer: %+v", got)
	}
	push([]string{"refs/heads/agent/fix", "refs/heads/main"}, "")
	if got := approvals(); len(got) != 1 || got[0].Summary != "Push in github.com/o/r: agent/fix, main" {
		t.Fatalf("a push that also moves main went through: %+v", got)
	}
	push([]string{"refs/heads/agent/fix"}, "gzip")
	if got := approvals(); len(got) != 2 || !strings.Contains(got[1].Summary, unreadRefs) {
		t.Fatalf("a compressed push went through: %+v", got)
	}
}

func TestARuleCredentialReplacesTheHosts(t *testing.T) {
	h := newHarnessWith(t, `
[secrets.github]
command = ["true"]

[[http]]
host = "github.com"
credential = { secret = "github", scheme = "basic", username = "oauth2" }
default = "allow"

[[http.rules]]
method = "*"
path = "/api/v4/**"
action = "allow"
credential = { secret = "github", scheme = "header", header = "PRIVATE-TOKEN" }
`)
	req, _ := http.NewRequest(http.MethodGet, "https://github.com/api/v4/projects", nil)
	req.Header.Set("Authorization", "Bearer brought-by-the-agent")
	req.Header.Set("PRIVATE-TOKEN", "placeholder")
	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	got, _ := h.upstream.last(t)
	if got.Header.Get("Private-Token") != "real-token" || got.Header.Get("Authorization") != "" {
		t.Fatalf("upstream headers: %v", got.Header)
	}
	resp, err = h.client().Get("https://github.com/group/proj.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatal(err)
	}
	_ = body(t, resp)
	got, _ = h.upstream.last(t)
	if !strings.HasPrefix(got.Header.Get("Authorization"), "Basic ") || got.Header.Get("Private-Token") != "" {
		t.Fatalf("a path no rule credential covers must get the host's: %v", got.Header)
	}
}

func TestAPortReachesOnlyTheHostsThatNameIt(t *testing.T) {
	h := newHarnessWith(t, `
[secrets.github]
command = ["true"]

[egress]
allow = ["example.com:8443"]

[[http]]
host = "github.com:8443"
credential = { secret = "github", scheme = "bearer" }
default = "allow"
`)
	resp, err := h.client().Get("https://example.com:8443/x")
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != http.StatusOK {
		t.Fatalf("a named port: status %d: %s", resp.StatusCode, b)
	}
	for _, refused := range []string{"https://example.com:9443/x", "https://example.com/x"} {
		resp, err := h.client().Get(refused)
		if err == nil {
			_ = body(t, resp)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s: status %d", refused, resp.StatusCode)
			}
		}
	}
	resp, err = h.client().Get("https://github.com:8443/api/v1/repos")
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != http.StatusOK {
		t.Fatalf("an inspected host on a port: status %d: %s", resp.StatusCode, b)
	}
	if got, _ := h.upstream.last(t); got.Header.Get("Authorization") != "Bearer real-token" {
		t.Fatalf("the credential must reach a host on its port: %v", got.Header)
	}
}

func canonicalPath(u *url.URL) bool {
	_, ok := matchPath(u, false)
	return ok
}

func TestEncodedSlashesStayInsideTheirSegment(t *testing.T) {
	for raw, want := range map[string]string{
		"/api/v4/projects/group%2Fsub%2Fproj/merge_requests": "/api/v4/projects/group%2Fsub%2Fproj/merge_requests",
		"/api/v4/projects/a%2fb/ho%6Fks":                     "/api/v4/projects/a%2Fb/hooks",
		"/api/v4/projects/42":                                "/api/v4/projects/42",
	} {
		u, err := url.Parse("https://gitlab.com" + raw)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := matchPath(u, true)
		if !ok || got != want {
			t.Errorf("matchPath(%q) = %q, %v; want %q", raw, got, ok, want)
		}
		if strings.Contains(strings.ToLower(raw), "%2f") {
			if _, ok := matchPath(u, false); ok {
				t.Errorf("%q must be refused on a host without encoded_slashes", raw)
			}
		}
	}
	for _, raw := range []string{"/api/v4/projects/a%2F..%2Fb", "/api/v4/projects/a%00b", "/a%2Fb/%2E%2E/hooks", "/a%5Cb"} {
		u, err := url.Parse("https://gitlab.com" + raw)
		if err != nil {
			continue
		}
		if got, ok := matchPath(u, true); ok {
			t.Errorf("matchPath(%q) = %q, accepted", raw, got)
		}
	}
	pattern, _ := profile.ParsePathPattern("/api/v4/projects/*/hooks/**")
	u, _ := url.Parse("https://gitlab.com/api/v4/projects/a%2Fb/ho%6Fks/1")
	if got, _ := matchPath(u, true); !pattern.Match(got) {
		t.Errorf("an encoded letter must not slip past a rule: %q", got)
	}
}

func TestAGRPCCallGetsTheCredentialOverHTTP2WithItsTrailers(t *testing.T) {
	h := newHarness(t)
	pool := h.upCA.Pool()
	pool.AppendCertsFromPEM(h.session.CertPEM())
	client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(h.proxyURL),
		TLSClientConfig:   &tls.Config{RootCAs: pool},
		ForceAttemptHTTP2: true,
	}, Timeout: 10 * time.Second}
	req, _ := http.NewRequest(http.MethodPost, "https://api.github.com/build.bazel.remote.execution.v2.Capabilities/GetCapabilities", strings.NewReader("\x00\x00\x00\x00\x00"))
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	req.Header.Set("Authorization", "Bearer placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = body(t, resp)
	if resp.ProtoMajor != 2 || resp.Header.Get("X-Upstream-Proto") != "HTTP/2.0" {
		t.Fatalf("jail side %s, upstream side %s: gRPC needs HTTP/2 on both", resp.Proto, resp.Header.Get("X-Upstream-Proto"))
	}
	if resp.Trailer.Get("Grpc-Status") != "0" {
		t.Errorf("trailers = %v: gRPC reports its status in them", resp.Trailer)
	}
	if got, _ := h.upstream.last(t); got.Header.Get("Authorization") != "Bearer real-token" {
		t.Errorf("upstream Authorization = %q", got.Header.Get("Authorization"))
	}
}

type heldApprover struct {
	release chan struct{}
}

func (a heldApprover) Submit(context.Context, approval.Request, time.Duration) (approval.Decision, error) {
	<-a.release
	return approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingOnce}, nil
}

type waitNotes struct {
	mu    sync.Mutex
	calls []string
	heard chan struct{}
}

func (w *waitNotes) Waiting(_ Identity, summary string) {
	w.mu.Lock()
	w.calls = append(w.calls, summary)
	w.mu.Unlock()
	close(w.heard)
}

func (w *waitNotes) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.calls)
}

func sendRelease(t *testing.T, h *harness, notes *waitNotes, approver Approver, after time.Duration) {
	srv := New(Config{Profile: "t", ApprovalTTL: time.Second, UpstreamRoots: h.upCA.Pool(), Waiting: notes, WaitingAfter: after}, loadPolicy(t), approver, mapSecrets{"github": "t"}, h.session, h.dialer(), h.events)
	req := httptest.NewRequest(http.MethodPost, "https://api.github.com/repos/acme/app/releases", strings.NewReader(`{}`))
	host, _ := srv.policy.Intercepted("api.github.com")
	srv.intercepted(httptest.NewRecorder(), req, "api.github.com", "api.github.com", host)
}

func TestAHeldRequestTellsTheCallerAfterTheDelay(t *testing.T) {
	h := newHarness(t)
	notes := &waitNotes{heard: make(chan struct{})}
	approver := heldApprover{release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		sendRelease(t, h, notes, approver, 10*time.Millisecond)
		close(done)
	}()
	select {
	case <-notes.heard:
	case <-time.After(5 * time.Second):
		t.Fatal("the caller heard nothing while the request was held")
	}
	close(approver.release)
	<-done
	if notes.calls[0] != "Create a GitHub release in api.github.com/repos/acme/app" {
		t.Errorf("summary = %q", notes.calls[0])
	}
}

func TestAnAnsweredRequestStaysQuiet(t *testing.T) {
	h := newHarness(t)
	notes := &waitNotes{heard: make(chan struct{})}
	sendRelease(t, h, notes, h.approver, time.Hour)
	if n := notes.count(); n != 0 {
		t.Errorf("%d hints for a request answered at once", n)
	}
}

func TestReverseProxyErrorsGoToTheEventLog(t *testing.T) {
	rec := &events{}
	s := &Server{recorder: rec}
	log := eventLog{s: s, host: "example.com", method: "POST", path: "/stream"}
	if _, err := log.Write([]byte("httputil: ReverseProxy read error during body copy: client disconnected\n")); err != nil {
		t.Fatal(err)
	}
	if len(rec.list) != 1 || rec.list[0].Kind != "error" || rec.list[0].Host != "example.com" || rec.list[0].Reason != "httputil: ReverseProxy read error during body copy: client disconnected" {
		t.Fatalf("events: %+v", rec.list)
	}
}

type rejectingSecrets struct {
	mapSecrets
	mu       sync.Mutex
	rejected []string
}

func (r *rejectingSecrets) Reject(name, token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rejected = append(r.rejected, name+":"+token)
}

type refusingUpstream struct{}

func (refusingUpstream) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusUnauthorized)
}

func TestARefusedTokenIsReportedToTheStoreSoTheNextRequestUsesANewOne(t *testing.T) {
	store := &rejectingSecrets{mapSecrets: mapSecrets{"github": "real-token"}}
	h := newHarnessWithSecrets(t, loadPolicy(t), &upstream{}, refusingUpstream{}, store)
	resp, err := h.client().Get("https://api.github.com/user")
	if err != nil {
		t.Fatal(err)
	}
	_ = body(t, resp)
	store.mu.Lock()
	defer store.mu.Unlock()
	if resp.StatusCode != http.StatusUnauthorized || len(store.rejected) != 1 || store.rejected[0] != "github:real-token" {
		t.Errorf("status %d, rejected %v", resp.StatusCode, store.rejected)
	}
}
