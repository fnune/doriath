package containers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fnune/girdle/internal/approval"
)

// fakePodman answers on a unix socket like the parts of podman the broker
// relays: JSON replies, a followed log, and attach in both hijack styles.
type fakePodman struct {
	mu    sync.Mutex
	paths []string
	// more releases the second log line.
	more chan struct{}
}

func (f *fakePodman) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()
	switch {
	case strings.HasSuffix(r.URL.Path, "/attach"):
		f.attach(w, r)
	case strings.HasSuffix(r.URL.Path, "/logs"):
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "line 1\n")
		_ = http.NewResponseController(w).Flush()
		<-f.more
		_, _ = io.WriteString(w, "line 2\n")
	case strings.HasSuffix(r.URL.Path, "/containers/create"):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"Id":"abc","Warnings":[]}`)
	default:
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}
}

// attach echoes each line, as a container running cat would, until stdin
// closes.
func (f *fakePodman) attach(w http.ResponseWriter, r *http.Request) {
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if r.Header.Get("Upgrade") != "" {
		_, _ = io.WriteString(conn, "HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
	} else {
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.docker.raw-stream\r\n\r\n")
	}
	for {
		line, err := brw.ReadString('\n')
		if line != "" {
			_, _ = io.WriteString(conn, "echo: "+line)
		}
		if err != nil {
			_, _ = io.WriteString(conn, "bye\n")
			return
		}
	}
}

func (f *fakePodman) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

type fakeApprover struct {
	verdict approval.Verdict
	mu      sync.Mutex
	asked   []approval.Request
}

func (a *fakeApprover) Submit(_ context.Context, req approval.Request, _ time.Duration) (approval.Decision, error) {
	a.mu.Lock()
	a.asked = append(a.asked, req)
	a.mu.Unlock()
	return approval.Decision{Verdict: a.verdict, Lasting: approval.LastingOnce}, nil
}

type events struct {
	mu   sync.Mutex
	list []Event
}

func (e *events) ContainerAPI(ev Event) {
	e.mu.Lock()
	e.list = append(e.list, ev)
	e.mu.Unlock()
}

func (e *events) kinds() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, ev := range e.list {
		out = append(out, ev.Kind)
	}
	return out
}

type harness struct {
	podman   *fakePodman
	approver *fakeApprover
	events   *events
	socket   string
	client   *http.Client
}

func listenUnix(t *testing.T, name string) net.Listener {
	t.Helper()
	l, err := net.Listen("unix", filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		podman:   &fakePodman{more: make(chan struct{})},
		approver: &fakeApprover{verdict: approval.VerdictAllow},
		events:   &events{},
	}
	up := listenUnix(t, "podman.sock")
	srv := &http.Server{Handler: h.podman, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(up) }()
	t.Cleanup(func() { _ = srv.Close() })

	policy := Policy{
		Images: []string{"docker.io/library/*"},
		Mounts: []Mount{{Path: "/work"}, {Path: "/ro", ReadOnly: true}},
	}
	b := New(policy, up.Addr().String(), h.approver, h.events, Config{Session: "s1", Profile: "dev", ApprovalTTL: time.Second})
	l := listenUnix(t, "broker.sock")
	go func() { _ = b.Serve(l) }()
	h.socket = l.Addr().String()
	h.client = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", h.socket)
		},
	}}
	return h
}

func (h *harness) do(t *testing.T, method, path, body string) (int, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, "http://d"+path, r)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(data)
}

func message(t *testing.T, body string) string {
	t.Helper()
	var m struct{ Message string }
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("not a JSON error: %q", body)
	}
	return m.Message
}

func TestCreateAllowedAndRefused(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		status  int
		message string
	}{
		{"allowed", `{"Image":"alpine","HostConfig":{"Binds":["/work:/w"],"NetworkMode":"host"}}`, http.StatusCreated, ""},
		{"privileged", `{"Image":"alpine","HostConfig":{"Privileged":true}}`, http.StatusForbidden, "girdle: privileged containers are not allowed"},
		{"bind outside", `{"Image":"alpine","HostConfig":{"Binds":["/home/u/.ssh:/s:ro"]}}`, http.StatusForbidden, "outside the mounts and caches of profile \"dev\""},
		{"read-only bind writable", `{"Image":"alpine","HostConfig":{"Binds":["/ro/x:/x"]}}`, http.StatusForbidden, "read-only in profile \"dev\""},
		{"read-only bind ro", `{"Image":"alpine","HostConfig":{"Binds":["/ro/x:/x:ro"]}}`, http.StatusCreated, ""},
		{"image not allowed", `{"Image":"quay.io/evil/miner"}`, http.StatusForbidden, "image quay.io/evil/miner:latest is not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			status, body := h.do(t, http.MethodPost, "/v1.41/containers/create?name=x", tt.body)
			if status != tt.status {
				t.Fatalf("status %d: %s", status, body)
			}
			if tt.message != "" && !strings.Contains(message(t, body), tt.message) {
				t.Fatalf("message %q lacks %q", message(t, body), tt.message)
			}
			forwarded := len(h.podman.seen()) > 0
			if forwarded != (tt.status != http.StatusForbidden) {
				t.Fatalf("forwarded = %v for status %d", forwarded, status)
			}
		})
	}
}

func TestRefusalIsRecorded(t *testing.T) {
	h := newHarness(t)
	h.do(t, http.MethodPost, "/libpod/containers/create", `{"image":"alpine","privileged":true}`)
	got := h.events.kinds()
	if len(got) != 1 || got[0] != "denied" {
		t.Fatalf("events %v", got)
	}
}

func TestVersionPrefixIsForwardedAsSent(t *testing.T) {
	h := newHarness(t)
	if status, body := h.do(t, http.MethodGet, "/v5.0.0/libpod/containers/json", ""); status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	if got := h.podman.seen(); len(got) != 1 || got[0] != "/v5.0.0/libpod/containers/json" {
		t.Fatalf("upstream saw %v", got)
	}
	if status, _ := h.do(t, http.MethodPost, "/v1.41/plugins/pull", ""); status != http.StatusForbidden {
		t.Fatalf("versioned plugin pull: %d", status)
	}
}

func TestUnknownEndpointRefused(t *testing.T) {
	h := newHarness(t)
	status, body := h.do(t, http.MethodPost, "/libpod/play/kube", "apiVersion: v1")
	if status != http.StatusForbidden || !strings.Contains(message(t, body), "kube YAML") {
		t.Fatalf("status %d: %s", status, body)
	}
	status, body = h.do(t, http.MethodGet, "/grpc", "")
	if status != http.StatusForbidden || !strings.HasPrefix(message(t, body), "girdle: ") {
		t.Fatalf("status %d: %s", status, body)
	}
	if got := h.podman.seen(); len(got) != 0 {
		t.Fatalf("forwarded %v", got)
	}
}

func TestBodyTooLarge(t *testing.T) {
	h := newHarness(t)
	big := `{"Image":"alpine","Labels":{"x":"` + strings.Repeat("a", maxInspectedBody) + `"}}`
	if status, _ := h.do(t, http.MethodPost, "/containers/create", big); status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", status)
	}
}

func TestPushApproval(t *testing.T) {
	for _, v := range []approval.Verdict{approval.VerdictAllow, approval.VerdictDeny} {
		t.Run(string(v), func(t *testing.T) {
			h := newHarness(t)
			h.approver.verdict = v
			status, body := h.do(t, http.MethodPost, "/v5.0.0/libpod/images/localhost/app:1/push?destination=ghcr.io/acme/app:1", "")
			if len(h.approver.asked) != 1 {
				t.Fatalf("asked %d times", len(h.approver.asked))
			}
			req := h.approver.asked[0]
			if req.Summary != "Push container image localhost/app:1 to ghcr.io/acme/app:1" || req.Scope != "containers push ghcr.io/acme/app:1" || req.Session != "s1" || req.Kind != KindContainers {
				t.Fatalf("request %+v", req)
			}
			if v == approval.VerdictAllow {
				if status != http.StatusOK || len(h.podman.seen()) != 1 {
					t.Fatalf("status %d: %s", status, body)
				}
				return
			}
			if status != http.StatusForbidden || !strings.Contains(message(t, body), "was denied") || len(h.podman.seen()) != 0 {
				t.Fatalf("status %d: %s", status, body)
			}
		})
	}
}

// attachRoundTrip sends a line through attach and checks the echo, then
// half-closes and expects the rest of the output.
func attachRoundTrip(t *testing.T, h *harness, upgrade bool) {
	t.Helper()
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	headers := "Content-Length: 0\r\n"
	if upgrade {
		headers += "Connection: Upgrade\r\nUpgrade: tcp\r\n"
	}
	if _, err := fmt.Fprintf(conn, "POST /v5.0.0/libpod/containers/abc/attach?stream=true&stdin=true HTTP/1.1\r\nHost: d\r\n%s\r\n", headers); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := http.StatusOK
	if upgrade {
		want = http.StatusSwitchingProtocols
	}
	if resp.StatusCode != want {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if _, err := io.WriteString(conn, "hello\n"); err != nil {
		t.Fatal(err)
	}
	line, err := br.ReadString('\n')
	if err != nil || line != "echo: hello\n" {
		t.Fatalf("read %q, %v", line, err)
	}
	if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(br)
	if err != nil || string(rest) != "bye\n" {
		t.Fatalf("rest %q, %v", rest, err)
	}
}

func TestAttachUpgradeStreamsBothWays(t *testing.T) {
	attachRoundTrip(t, newHarness(t), true)
}

func TestAttachRawStreamWithoutUpgrade(t *testing.T) {
	attachRoundTrip(t, newHarness(t), false)
}

func TestLogsFollowStreams(t *testing.T) {
	h := newHarness(t)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://d/v1.41/containers/abc/logs?follow=1&stdout=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	line, err := br.ReadString('\n')
	if err != nil || line != "line 1\n" {
		t.Fatalf("first line %q, %v", line, err)
	}
	close(h.podman.more)
	line, err = br.ReadString('\n')
	if err != nil || line != "line 2\n" {
		t.Fatalf("second line %q, %v", line, err)
	}
	if len(resp.TransferEncoding) == 0 || resp.TransferEncoding[0] != "chunked" {
		t.Fatalf("transfer encoding %v", resp.TransferEncoding)
	}
}
