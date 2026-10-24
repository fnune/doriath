package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/profile"
)

type fakeHolder struct {
	allowed bool
	pending string

	mu    sync.Mutex
	asked []string
}

func (f *fakeHolder) HoldHost(_ context.Context, host, _ string) (bool, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, host)
	return f.allowed, f.pending
}

type refusingDialer struct{}

func (refusingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("connection refused")
}

func (h *harness) server(t *testing.T, p *profile.Profile, cfg Config, dialer Dialer) *Server {
	t.Helper()
	cfg.Profile = "t"
	cfg.ApprovalTTL = time.Second
	cfg.UpstreamRoots = h.upCA.Pool()
	return New(cfg, p, h.approver, mapSecrets{"github": "real-token", "notion": "notion-token"}, h.session, dialer, h.events)
}

func serveAs(srv *Server, exe string, req *http.Request) *httptest.ResponseRecorder {
	if exe != "" {
		req = req.WithContext(withIdentity(req.Context(), Identity{PID: 9, Exe: exe}))
	}
	rec := httptest.NewRecorder()
	srv.handle(rec, req)
	return rec
}

func deniedMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Header().Get("X-Doriath-Denied") != "1" {
		t.Fatalf("status %d without the denial header: %s", rec.Code, rec.Body)
	}
	var msg struct{ Message string }
	if err := json.Unmarshal(rec.Body.Bytes(), &msg); err != nil {
		t.Fatalf("denial body %q: %v", rec.Body, err)
	}
	return msg.Message
}

func TestUnlistedHostWaitsForYourAnswer(t *testing.T) {
	for name, tc := range map[string]struct {
		holder      *fakeHolder
		wantStatus  int
		wantMessage []string
	}{
		"allowed while it waits": {holder: &fakeHolder{allowed: true}, wantStatus: http.StatusOK},
		"still pending": {
			holder:      &fakeHolder{pending: "r7"},
			wantStatus:  http.StatusForbidden,
			wantMessage: []string{"approval r7 is pending", "run: `doriath request wait evil.example`"},
		},
		"refused": {
			holder:      &fakeHolder{},
			wantStatus:  http.StatusForbidden,
			wantMessage: []string{`evil.example is not in profile "t"`, "add it to [egress] allow"},
		},
		"nobody to ask": {
			wantStatus:  http.StatusForbidden,
			wantMessage: []string{`evil.example is not in profile "t"`, "add it to [egress] allow"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			cfg := Config{}
			if tc.holder != nil {
				cfg.Holder = tc.holder
			}
			srv := h.server(t, loadPolicy(t), cfg, h.dialer())
			rec := serveAs(srv, "/nix/store/abc-curl/bin/curl", httptest.NewRequest(http.MethodGet, "http://evil.example/x", nil))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			if tc.wantStatus == http.StatusOK {
				if h.upstream.count() != 1 {
					t.Fatal("an allowed host must reach upstream")
				}
				return
			}
			msg := deniedMessage(t, rec)
			for _, want := range tc.wantMessage {
				if !strings.Contains(msg, want) {
					t.Errorf("message %q lacks %q", msg, want)
				}
			}
			if h.upstream.count() != 0 || !h.events.has("denied", "evil.example") {
				t.Fatal("a refused host must not reach upstream, and the denial must be recorded")
			}
		})
	}
}

func TestHostForSomeProgramsNamesThemAndAsksNobody(t *testing.T) {
	h := newHarness(t)
	holder := &fakeHolder{allowed: true}
	p := loadProfile(t, `
[egress]
allow = ["example.com"]

[[egress.programs]]
binaries = ["gh"]
allow = ["uploads.example"]
`)
	srv := h.server(t, p, Config{Holder: holder}, h.dialer())
	get := func(exe string) *httptest.ResponseRecorder {
		return serveAs(srv, exe, httptest.NewRequest(http.MethodGet, "http://uploads.example/x", nil))
	}

	rec := get("/nix/store/abc-curl/bin/curl")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("curl: status %d", rec.Code)
	}
	if msg := deniedMessage(t, rec); msg != `doriath: profile "t" lets only gh reach uploads.example` {
		t.Errorf("message = %q", msg)
	}
	if len(holder.asked) != 0 {
		t.Error("you are not asked about a host the profile gave to other programs")
	}
	if rec := get("/nix/store/abc-gh/bin/gh"); rec.Code != http.StatusOK || h.upstream.count() != 1 {
		t.Fatalf("gh: status %d: %s", rec.Code, rec.Body)
	}
}

func TestMCPToolCallsFollowTheServersLists(t *testing.T) {
	p := loadProfile(t, `
[secrets.notion]
file = "/run/secrets/notion"

[[mcp]]
name = "notion"
url = "https://mcp.example.com/mcp"
secret = "notion"
approve = ["notion-create-*"]
deny = ["notion-delete-*"]
`)
	call := func(tools ...string) string {
		var msgs []string
		for i, tool := range tools {
			msgs = append(msgs, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q}}`, i, tool))
		}
		if len(msgs) == 1 {
			return msgs[0]
		}
		return "[" + strings.Join(msgs, ",") + "]"
	}
	for name, tc := range map[string]struct {
		body        string
		wantStatus  int
		wantSummary string
		wantScope   string
	}{
		"a listed tool to approve": {
			body:        call("notion-create-page"),
			wantStatus:  http.StatusOK,
			wantSummary: "Call notion tool notion-create-page",
			wantScope:   "http POST mcp.example.com /** mcp notion-create-page",
		},
		"a denied tool":               {body: call("notion-delete-page"), wantStatus: http.StatusForbidden},
		"a denied tool in a batch":    {body: call("notion-search", "notion-delete-page"), wantStatus: http.StatusForbidden},
		"another tool by the default": {body: call("notion-search"), wantStatus: http.StatusOK},
		"listing tools":               {body: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, wantStatus: http.StatusOK},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			srv := h.server(t, p, Config{}, h.dialer())
			host, _ := p.Intercepted("mcp.example.com")
			req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/mcp", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			srv.intercepted(rec, req, "mcp.example.com", "mcp.example.com", host)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			h.approver.mu.Lock()
			requests := h.approver.requests
			h.approver.mu.Unlock()
			switch {
			case tc.wantSummary == "" && len(requests) != 0:
				t.Errorf("asked about %+v", requests)
			case tc.wantSummary != "" && (len(requests) != 1 || requests[0].Summary != tc.wantSummary || requests[0].Scope != tc.wantScope):
				t.Errorf("approval requests = %+v", requests)
			}
			if tc.wantStatus != http.StatusOK {
				if h.upstream.count() != 0 {
					t.Fatal("a denied tool call reached upstream")
				}
				return
			}
			got, gotBody := h.upstream.last(t)
			if got.Header.Get("Authorization") != "Bearer notion-token" || string(gotBody) != tc.body {
				t.Fatalf("upstream got Authorization %q and body %q", got.Header.Get("Authorization"), gotBody)
			}
		})
	}
}

func TestRefusedApprovalSaysWhy(t *testing.T) {
	for name, tc := range map[string]struct {
		verdict approval.Verdict
		err     error
		want    string
	}{
		"denied with a reason": {verdict: approval.VerdictDeny, want: "doriath: Create a GitHub release in api.github.com/repos/a/b was denied: not today"},
		"expired":              {verdict: approval.VerdictNone, want: "doriath: Create a GitHub release in api.github.com/repos/a/b: nobody approved it in time"},
		"queue unreachable":    {err: errors.New("no queue"), want: "doriath: Create a GitHub release in api.github.com/repos/a/b was denied"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.approver.verdict, h.approver.err = tc.verdict, tc.err
			p := loadPolicy(t)
			host, _ := p.Intercepted("api.github.com")
			req := httptest.NewRequest(http.MethodPost, "https://api.github.com/repos/a/b/releases", strings.NewReader("{}"))
			rec := httptest.NewRecorder()
			h.server(t, p, Config{}, h.dialer()).intercepted(rec, req, "api.github.com", "api.github.com", host)
			if rec.Code != http.StatusForbidden || h.upstream.count() != 0 {
				t.Fatalf("status %d, upstream %d", rec.Code, h.upstream.count())
			}
			if msg := deniedMessage(t, rec); msg != tc.want {
				t.Errorf("message = %q, want %q", msg, tc.want)
			}
		})
	}
}

func TestCredentialSchemes(t *testing.T) {
	h := newHarness(t)
	srv := h.server(t, loadPolicy(t), Config{}, h.dialer())
	for _, tc := range []struct {
		cred         profile.Credential
		header, want string
	}{
		{profile.Credential{Secret: "github", Scheme: profile.SchemeBearer}, "Authorization", "Bearer real-token"},
		{profile.Credential{Secret: "github", Scheme: profile.SchemeToken}, "Authorization", "token real-token"},
		{profile.Credential{Secret: "github", Scheme: profile.SchemeBasic, Username: "x-access-token"}, "Authorization", "Basic eC1hY2Nlc3MtdG9rZW46cmVhbC10b2tlbg=="},
		{profile.Credential{Secret: "github", Scheme: profile.SchemeHeader, Header: "Private-Token"}, "Private-Token", "real-token"},
	} {
		header, got, err := srv.credentialHeader(context.Background(), tc.cred)
		if err != nil || header != tc.header || got != tc.want {
			t.Errorf("%s: got %s: %q, %v; want %s: %q", tc.cred.Scheme, header, got, err, tc.header, tc.want)
		}
	}
}

func TestForwardProxyRefusesWhatItCannotRoute(t *testing.T) {
	h := newHarness(t)
	srv := h.server(t, loadPolicy(t), Config{}, h.dialer())
	for target, want := range map[string]string{
		"/x":                  "this is a forward proxy; send absolute URLs or CONNECT",
		"ftp://example.com/x": `unsupported scheme "ftp"`,
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.URL, _ = req.URL.Parse(target)
		rec := serveAs(srv, "", req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(deniedMessage(t, rec), want) {
			t.Errorf("%s: status %d: %s", target, rec.Code, rec.Body)
		}
	}
	if h.upstream.count() != 0 {
		t.Fatal("an unroutable request reached upstream")
	}
}

func TestUnreachableUpstreamSaysWhichHost(t *testing.T) {
	h := newHarness(t)
	srv := h.server(t, loadPolicy(t), Config{}, refusingDialer{})

	rec := serveAs(srv, "", httptest.NewRequest(http.MethodGet, "http://plain.example/x", nil))
	if msg := deniedMessage(t, rec); rec.Code != http.StatusBadGateway || !strings.Contains(msg, "upstream plain.example failed") {
		t.Errorf("plain HTTP: status %d: %s", rec.Code, msg)
	}

	resp := connectThrough(t, listen(t, srv), "example.com:443")
	if b, _ := io.ReadAll(resp.Body); resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(b), "cannot reach example.com") {
		t.Errorf("CONNECT: status %d: %s", resp.StatusCode, b)
	}
	if !h.events.has("error", "example.com") {
		t.Error("the failed dial was not recorded")
	}
}

func TestTunnelThatDoesNotStartWithTLSIsClosed(t *testing.T) {
	h := newHarness(t)
	conn, err := net.Dial("tcp", h.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("the tunnel answered bytes that were not a ClientHello")
	}
	if h.upstream.count() != 0 || !h.events.has("denied", "example.com") {
		t.Fatal("plain bytes in a tunnel must be refused and recorded")
	}
}

func listen(t *testing.T, srv *Server) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() { _ = srv.Serve(l) }()
	return l.Addr().String()
}

func connectThrough(t *testing.T, proxyAddr, target string) *http.Response {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
