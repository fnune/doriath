package proxy

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/profile"
)

const bridgeProfile = `
[secrets.claude]
keyring = true

[secrets.github]
keyring = true

[egress]
allow = ["bridge.example.com"]

[[http]]
host = "bridge.example.com"
default = "allow"
credential = { secret = "claude", scheme = "websocket", field = "oauth_token" }

[[http]]
host = "api.github.com"
credential = { secret = "github", scheme = "bearer" }
`

// fakeBridge is a server that takes the login in the first message of a
// WebSocket, as the Claude in Chrome bridge does.
type fakeBridge struct {
	mu       sync.Mutex
	headers  http.Header
	path     string
	received []wsFrame
	raw      []byte
	plain    int
}

func (b *fakeBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !isWebSocketUpgrade(r) {
		b.mu.Lock()
		b.plain++
		b.headers = r.Header.Clone()
		b.mu.Unlock()
		fmt.Fprint(w, "plain")
		return
	}
	b.mu.Lock()
	b.headers, b.path = r.Header.Clone(), r.URL.Path
	b.mu.Unlock()
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	fmt.Fprintf(brw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
	_ = brw.Flush()
	for {
		f, err := readFrame(brw.Reader, 1<<20)
		if err != nil {
			return
		}
		b.mu.Lock()
		b.received = append(b.received, f)
		b.raw = append(b.raw, f.raw...)
		b.mu.Unlock()
		if f.opcode == 0x8 {
			_, _ = conn.Write([]byte{0x88, 0})
			return
		}
		if f.opcode == 0x1 && strings.Contains(string(f.payload), `"connect"`) {
			_, _ = conn.Write(serverText(`{"type":"paired"}`))
		}
		if f.opcode == 0x1 && strings.Contains(string(f.payload), `"echo"`) {
			_, _ = conn.Write(serverText("echo:" + string(f.payload)))
		}
	}
}

func (b *fakeBridge) messages() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, f := range b.received {
		if f.opcode == 0x1 {
			out = append(out, string(f.payload))
		}
	}
	return out
}

func (b *fakeBridge) bytes() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.raw)
}

func serverText(s string) []byte {
	if len(s) < 126 {
		return append([]byte{0x81, byte(len(s))}, s...)
	}
	return append([]byte{0x81, 126, byte(len(s) >> 8), byte(len(s))}, s...)
}

func clientFrame(opcode byte, payload []byte) []byte {
	head := []byte{opcode | 0x80}
	switch n := len(payload); {
	case n < 126:
		head = append(head, 0x80|byte(n))
	case n <= 0xffff:
		head = append(head, 0x80|126, byte(n>>8), byte(n))
	default:
		head = append(head, 0x80|127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	key := make([]byte, 4)
	_, _ = rand.Read(key)
	frame := slices.Concat(head, key)
	for i, c := range payload {
		frame = append(frame, c^key[i%4])
	}
	return frame
}

// wsClient is a program in the jail: it asks the proxy to tunnel to the host,
// and speaks WebSocket over it.
type wsClient struct {
	conn net.Conn
	r    *bufio.Reader
	resp *http.Response
}

func (h *harness) wsDial(t *testing.T, path string, header http.Header) *wsClient {
	t.Helper()
	const host = "bridge.example.com"
	conn, err := net.Dial("tcp", h.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host)
	r := bufio.NewReader(conn)
	if status, err := r.ReadString('\n'); err != nil || !strings.Contains(status, "200") {
		t.Fatalf("CONNECT: %q, %v", status, err)
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	pool := h.upCA.Pool()
	pool.AppendCertsFromPEM(h.session.CertPEM())
	tc := tls.Client(conn, &tls.Config{RootCAs: pool, ServerName: host, NextProtos: []string{"http/1.1"}})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(tc, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", path, host)
	for k, vs := range header {
		for _, v := range vs {
			fmt.Fprintf(tc, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprint(tc, "\r\n")
	br := bufio.NewReader(tc)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &wsClient{conn: tc, r: br, resp: resp}
}

func (c *wsClient) send(t *testing.T, frame []byte) {
	t.Helper()
	if _, err := c.conn.Write(frame); err != nil {
		t.Fatal(err)
	}
}

func (c *wsClient) next(t *testing.T) wsFrame {
	t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	f, err := readFrame(c.r, 1<<20)
	if err != nil {
		t.Fatalf("read a frame: %v", err)
	}
	return f
}

func newBridgeHarness(t *testing.T) (*harness, *fakeBridge) {
	t.Helper()
	bridge := &fakeBridge{}
	return newHarnessServing(t, loadProfile(t, bridgeProfile), &upstream{}, bridge), bridge
}

func TestTheProxyPutsTheLoginInTheFirstMessageOfAWebSocket(t *testing.T) {
	h, bridge := newBridgeHarness(t)
	c := h.wsDial(t, "/chrome/user-1", http.Header{"Authorization": {"Bearer placeholder"}})
	if c.resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", c.resp.StatusCode)
	}
	c.send(t, clientFrame(0x1, []byte(`{"type":"connect","client_type":"claude-code","oauth_token":"doriath-placeholder"}`)))
	if f := c.next(t); f.opcode != 0x1 || string(f.payload) != `{"type":"paired"}` {
		t.Fatalf("the reply of the server = %+v", f)
	}
	var got map[string]string
	if msgs := bridge.messages(); len(msgs) != 1 || json.Unmarshal([]byte(msgs[0]), &got) != nil {
		t.Fatalf("messages = %v", msgs)
	}
	if got["oauth_token"] != "real-login" || got["type"] != "connect" || got["client_type"] != "claude-code" {
		t.Errorf("the server got %v", got)
	}
	if strings.Contains(bridge.bytes(), "doriath-placeholder") {
		t.Error("the placeholder reached the server")
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.path != "/chrome/user-1" || bridge.headers.Get("Authorization") != "" {
		t.Errorf("path %q, Authorization %q", bridge.path, bridge.headers.Get("Authorization"))
	}
	if !h.events.has("request", "bridge.example.com") {
		t.Error("the upgrade is not recorded")
	}
}

func TestFramesPassBothWaysAndOnlyTheFirstMessageChanges(t *testing.T) {
	h, bridge := newBridgeHarness(t)
	c := h.wsDial(t, "/chrome/u", nil)
	c.send(t, clientFrame(0x9, []byte("ping")))
	c.send(t, clientFrame(0x1, []byte(`{"type":"connect","oauth_token":"x"}`)))
	c.next(t)
	second := `{"type":"echo","oauth_token":"doriath-placeholder"}`
	c.send(t, clientFrame(0x1, []byte(second)))
	if f := c.next(t); string(f.payload) != "echo:"+second {
		t.Fatalf("echo = %q", f.payload)
	}
	large := strings.Repeat("a", 100<<10)
	c.send(t, clientFrame(0x2, []byte(large)))
	c.send(t, clientFrame(0x1, []byte(`{"type":"echo"}`)))
	if f := c.next(t); string(f.payload) != `echo:{"type":"echo"}` {
		t.Fatalf("after a large binary frame = %q", f.payload)
	}
	c.send(t, clientFrame(0x8, []byte{0x03, 0xe8}))
	if f := c.next(t); f.opcode != 0x8 {
		t.Errorf("the close frame of the server = %+v", f)
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	var kinds []byte
	for _, f := range bridge.received {
		kinds = append(kinds, f.opcode)
	}
	if string(kinds) != string([]byte{0x9, 0x1, 0x1, 0x2, 0x1, 0x8}) {
		t.Errorf("frames at the server = %v", kinds)
	}
	if !strings.Contains(string(bridge.received[1].payload), `"oauth_token":"real-login"`) || string(bridge.received[2].payload) != second || len(bridge.received[3].payload) != len(large) {
		t.Errorf("payloads: first %q, second %q", bridge.received[1].payload, bridge.received[2].payload)
	}
}

func TestAFirstMessageWithoutTheFieldPassesAsItCame(t *testing.T) {
	h, bridge := newBridgeHarness(t)
	c := h.wsDial(t, "/chrome/u", nil)
	hello := `{"type":"echo","note":"no login here"}`
	c.send(t, clientFrame(0x1, []byte(hello)))
	c.next(t)
	if msgs := bridge.messages(); len(msgs) != 1 || msgs[0] != hello {
		t.Errorf("messages = %v", msgs)
	}
}

func TestAnOrdinaryRequestToTheHostGetsNoLogin(t *testing.T) {
	h, bridge := newBridgeHarness(t)
	req, _ := http.NewRequest(http.MethodGet, "https://bridge.example.com/health", nil)
	req.Header.Set("Authorization", "Bearer placeholder")
	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if got := body(t, resp); got != "plain" {
		t.Fatalf("body %q", got)
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.headers.Get("Authorization") != "Bearer placeholder" {
		t.Errorf("Authorization = %q: a request that is no WebSocket gets no login", bridge.headers.Get("Authorization"))
	}
}

func TestOtherHostsKeepTheirHeaderCredential(t *testing.T) {
	h := newHarnessFor(t, loadProfile(t, bridgeProfile))
	req, _ := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = body(t, resp)
	if got, _ := h.upstream.last(t); got.Header.Get("Authorization") != "Bearer real-token" {
		t.Errorf("Authorization = %q", got.Header.Get("Authorization"))
	}
}

func TestAMissingLoginStopsTheWebSocketBeforeItOpens(t *testing.T) {
	p := loadProfile(t, strings.Replace(bridgeProfile, `credential = { secret = "claude", scheme = "websocket"`, `credential = { secret = "gone", scheme = "websocket"`, 1)+"\n[secrets.gone]\nkeyring = true\n")
	bridge := &fakeBridge{}
	h := newHarnessServing(t, p, &upstream{}, bridge)
	c := h.wsDial(t, "/chrome/u", nil)
	if c.resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status %d", c.resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, c.resp.Body)
	if bridge.messages() != nil || bridge.path != "" {
		t.Error("the server saw the upgrade")
	}
}

func TestTheWebSocketSchemeNeedsAField(t *testing.T) {
	for toml, want := range map[string]string{
		`[secrets.c]
keyring = true
[[http]]
host = "a.example"
credential = { secret = "c", scheme = "websocket" }`: "needs the name of a field",
		`[secrets.c]
keyring = true
[[http]]
host = "a.example"
credential = { secret = "c", scheme = "bearer", field = "oauth_token" }`: "field is only used with the websocket scheme",
	} {
		l := &profile.Loader{Profiles: mapFS{"t.toml": toml}, Home: "/home/u"}
		if _, err := l.Load("t"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want %q", err, want)
		}
	}
}

// reasonOf waits for the audit event that tells what the proxy did with the
// first message, which it records when the connection ends.
func (e *events) websocketReason(t *testing.T) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		e.mu.Lock()
		for _, ev := range e.list {
			if ev.Kind == "websocket" {
				e.mu.Unlock()
				return ev.Reason
			}
		}
		e.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no websocket event")
	return ""
}

func TestTheServerCannotAgreeToCompressMessages(t *testing.T) {
	h, bridge := newBridgeHarness(t)
	c := h.wsDial(t, "/chrome/u", http.Header{"Sec-WebSocket-Extensions": {"permessage-deflate; client_max_window_bits"}})
	c.send(t, clientFrame(0x1, []byte(`{"type":"connect","oauth_token":"doriath-placeholder"}`)))
	c.next(t)
	bridge.mu.Lock()
	got := bridge.headers.Get("Sec-WebSocket-Extensions")
	bridge.mu.Unlock()
	if got != "" {
		t.Errorf("the server was offered %q", got)
	}
	_ = c.conn.Close()
	if reason := h.events.websocketReason(t); reason != "set the field oauth_token in the first message" {
		t.Errorf("the audit event says %q", reason)
	}
}

func TestACompressedFirstMessageIsLeftAsItCameAndTheAuditLogSaysWhy(t *testing.T) {
	h, bridge := newBridgeHarness(t)
	c := h.wsDial(t, "/chrome/u", nil)
	frame := clientFrame(0x1, []byte(`{"type":"echo"}`))
	frame[0] |= 0x40
	c.send(t, frame)
	c.send(t, clientFrame(0x1, []byte(`{"type":"echo","after":true}`)))
	c.next(t)
	_ = c.conn.Close()
	if reason := h.events.websocketReason(t); reason != "left the first message as it came: it is compressed by an extension" {
		t.Errorf("the audit event says %q", reason)
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if len(bridge.received) < 2 || !bridge.received[0].rsv {
		t.Errorf("the server saw %d frames, first compressed: %v", len(bridge.received), len(bridge.received) > 0 && bridge.received[0].rsv)
	}
}

func TestTheAuditEventForAFirstMessageWithoutTheFieldSaysSo(t *testing.T) {
	h, _ := newBridgeHarness(t)
	c := h.wsDial(t, "/chrome/u", nil)
	c.send(t, clientFrame(0x1, []byte(`{"type":"echo"}`)))
	c.next(t)
	_ = c.conn.Close()
	if reason := h.events.websocketReason(t); reason != "left the first message as it came: it is not a JSON object with the field oauth_token" {
		t.Errorf("the audit event says %q", reason)
	}
}
