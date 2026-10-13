package notify

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/fnune/girdle/internal/approval"
)

const busConfig = `<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path=SOCKET</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
`

// privateBus starts a session bus of its own, so the test neither needs nor
// disturbs a desktop.
func privateBus(t *testing.T) string {
	t.Helper()
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon is not installed; try nix-shell -p dbus")
	}
	dir, err := os.MkdirTemp("", "gn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	config := filepath.Join(dir, "bus.conf")
	if err := os.WriteFile(config, []byte(strings.Replace(busConfig, "SOCKET", filepath.Join(dir, "bus"), 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(daemon, "--config-file="+config, "--nofork", "--nopidfile", "--print-address")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	address, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("read the bus address: %v", err)
	}
	return strings.TrimSpace(address)
}

type shown struct {
	id      uint32
	summary string
	body    string
	actions []string
	hints   map[string]dbus.Variant
}

// fakeServer implements the parts of org.freedesktop.Notifications that
// girdle calls.
type fakeServer struct {
	conn *dbus.Conn

	mu     sync.Mutex
	next   uint32
	shown  []shown
	closed []uint32
}

func (s *fakeServer) Notify(_ string, _ uint32, _, summary, body string, actions []string, hints map[string]dbus.Variant, _ int32) (uint32, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	s.shown = append(s.shown, shown{id: s.next, summary: summary, body: body, actions: actions, hints: hints})
	return s.next, nil
}

func (s *fakeServer) CloseNotification(id uint32) *dbus.Error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = append(s.closed, id)
	return nil
}

func (s *fakeServer) GetCapabilities() ([]string, *dbus.Error) {
	return []string{"actions", "body", "body-markup"}, nil
}

func (s *fakeServer) last(t *testing.T) shown {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.shown) == 0 {
		t.Fatal("nothing was shown")
	}
	return s.shown[len(s.shown)-1]
}

func (s *fakeServer) invoke(t *testing.T, id uint32, action string) {
	t.Helper()
	if err := s.conn.Emit(objPath, iface+".ActionInvoked", id, action); err != nil {
		t.Fatal(err)
	}
}

func startServer(t *testing.T, address string) *fakeServer {
	t.Helper()
	conn, err := dbus.Connect(address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	s := &fakeServer{conn: conn}
	if err := conn.Export(s, objPath, iface); err != nil {
		t.Fatal(err)
	}
	reply, err := conn.RequestName(busName, dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("own %s: %v, %v", busName, reply, err)
	}
	return s
}

type recordingOpener struct {
	mu     sync.Mutex
	opened []string
}

func (o *recordingOpener) Open(url string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.opened = append(o.opened, url)
	return nil
}

func (o *recordingOpener) urls() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.opened)
}

type desktopEnv struct {
	server  *fakeServer
	desktop *Desktop
	opener  *recordingOpener
	address string
}

func newDesktopEnv(t *testing.T) *desktopEnv {
	t.Helper()
	address := privateBus(t)
	server := startServer(t, address)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", address)
	opener := &recordingOpener{}
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	d, err := NewDesktop(opener, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return &desktopEnv{server: server, desktop: d, opener: opener, address: address}
}

func (e *desktopEnv) notify(t *testing.T, req approval.Request) (uint32, <-chan approval.Decision, func()) {
	t.Helper()
	decisions := make(chan approval.Decision, 8)
	withdraw, err := e.desktop.Notify(context.Background(), req, func(d approval.Decision) { decisions <- d })
	if err != nil {
		t.Fatal(err)
	}
	return e.server.last(t).id, decisions, withdraw
}

// settle returns once the desktop's connection has read every message sent
// to it so far by conn, because the bus keeps the order of messages from one
// connection to another, and godbus queues signals as it reads them.
func (e *desktopEnv) settle(t *testing.T, conn *dbus.Conn) {
	t.Helper()
	if err := conn.Object(e.desktop.conn.Names()[0], "/").Call("org.freedesktop.DBus.Peer.Ping", 0).Err; err != nil {
		t.Fatal(err)
	}
}

func expectDecision(t *testing.T, decisions <-chan approval.Decision, want approval.Decision) {
	t.Helper()
	select {
	case got := <-decisions:
		if got != want {
			t.Fatalf("decision = %+v, want %+v", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("no decision, want %+v", want)
	}
}

func expectNoDecision(t *testing.T, decisions <-chan approval.Decision) {
	t.Helper()
	select {
	case got := <-decisions:
		t.Fatalf("unexpected decision %+v", got)
	default:
	}
}

var request = approval.Request{
	ID: "r1", Session: "s1", Profile: "kitchen", Agent: "claude", Kind: approval.KindTool,
	Summary: "Run: push the branch", Details: "git push origin <main>", Scope: "tool claude Bash git push",
	Expires: time.Date(2026, 10, 13, 12, 1, 0, 0, time.UTC),
}

func TestDesktopShowsAndDecides(t *testing.T) {
	e := newDesktopEnv(t)
	caps, err := e.desktop.Capabilities()
	if err != nil || !slices.Contains(caps, "actions") {
		t.Fatalf("capabilities = %v, %v", caps, err)
	}

	id, decisions, withdraw := e.notify(t, request)
	got := e.server.last(t)
	if got.summary != request.Summary {
		t.Errorf("summary = %q", got.summary)
	}
	for _, want := range []string{"Written by claude, not by girdle.", "<tt>git push origin &lt;main&gt;</tt>", "Profile kitchen, session s1.", "Expires in 1m0s."} {
		if !strings.Contains(got.body, want) {
			t.Errorf("body lacks %q: %q", want, got.body)
		}
	}
	if want := []string{"allow-once", "Allow once", "allow-session", "Allow for this session", "deny", "Deny"}; !slices.Equal(got.actions, want) {
		t.Errorf("actions = %v", got.actions)
	}
	if got.hints["urgency"].Value() != urgencyHi {
		t.Errorf("hints = %v", got.hints)
	}

	e.server.invoke(t, id, "allow-session")
	expectDecision(t, decisions, approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession, By: "desktop"})

	withdraw()
	e.server.mu.Lock()
	closed := slices.Clone(e.server.closed)
	e.server.mu.Unlock()
	if !slices.Equal(closed, []uint32{id}) {
		t.Errorf("closed = %v", closed)
	}
	e.server.invoke(t, id, "deny")
	_, later, _ := e.notify(t, request)
	e.server.invoke(t, e.server.last(t).id, "deny")
	expectDecision(t, later, approval.Decision{Verdict: approval.VerdictDeny, By: "desktop"})
	expectNoDecision(t, decisions)
}

// TestDesktopIgnoresOtherSenders checks that only the notification server can
// decide. Any program on the session bus can send a signal with the same
// path, interface and member, and the bus delivers a signal addressed to a
// connection whatever its match rules say.
func TestDesktopIgnoresOtherSenders(t *testing.T) {
	e := newDesktopEnv(t)
	id, decisions, _ := e.notify(t, request)

	imposter, err := dbus.Connect(e.address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = imposter.Close() }()
	if err := imposter.Emit(objPath, iface+".ActionInvoked", id, "allow-session"); err != nil {
		t.Fatal(err)
	}
	directed := &dbus.Message{
		Type: dbus.TypeSignal,
		Headers: map[dbus.HeaderField]dbus.Variant{
			dbus.FieldPath:        dbus.MakeVariant(dbus.ObjectPath(objPath)),
			dbus.FieldInterface:   dbus.MakeVariant(iface),
			dbus.FieldMember:      dbus.MakeVariant("ActionInvoked"),
			dbus.FieldDestination: dbus.MakeVariant(e.desktop.conn.Names()[0]),
			dbus.FieldSignature:   dbus.MakeVariant(dbus.SignatureOf(id, "")),
		},
		Body: []any{id, "allow-session"},
	}
	if call := imposter.Send(directed, nil); call.Err != nil {
		t.Fatal(call.Err)
	}
	e.settle(t, imposter)

	e.server.invoke(t, id, "deny")
	expectDecision(t, decisions, approval.Decision{Verdict: approval.VerdictDeny, By: "desktop"})
	expectNoDecision(t, decisions)
}

func TestDesktopOpenLink(t *testing.T) {
	e := newDesktopEnv(t)
	withLink := request
	withLink.URL = "https://github.com/fnune/app/pull/1"
	id, decisions, _ := e.notify(t, withLink)
	if got := e.server.last(t); !slices.Contains(got.actions, "open") || !strings.Contains(got.body, "Link: "+withLink.URL) {
		t.Errorf("a https link gets a button: %v %q", got.actions, got.body)
	}
	e.server.invoke(t, id, "open")
	e.server.invoke(t, id, "allow-once")
	expectDecision(t, decisions, approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingOnce, By: "desktop"})
	if got := e.opener.urls(); !slices.Equal(got, []string{withLink.URL}) {
		t.Errorf("opened %v", got)
	}

	unsafe := request
	unsafe.URL = "file:///etc/passwd"
	id, decisions, _ = e.notify(t, unsafe)
	if got := e.server.last(t); slices.Contains(got.actions, "open") || strings.Contains(got.body, "Link:") {
		t.Errorf("a file link gets no button: %v %q", got.actions, got.body)
	}
	e.server.invoke(t, id, "open")
	e.server.invoke(t, id, "deny")
	expectDecision(t, decisions, approval.Decision{Verdict: approval.VerdictDeny, By: "desktop"})
	if got := e.opener.urls(); len(got) != 1 {
		t.Errorf("opened %v", got)
	}
}

func TestDesktopNotificationClosed(t *testing.T) {
	e := newDesktopEnv(t)
	id, decisions, _ := e.notify(t, request)
	if err := e.server.conn.Emit(objPath, iface+".NotificationClosed", id, uint32(2)); err != nil {
		t.Fatal(err)
	}
	e.server.invoke(t, id, "allow-session")
	_, later, _ := e.notify(t, request)
	e.server.invoke(t, e.server.last(t).id, "deny")
	expectDecision(t, later, approval.Decision{Verdict: approval.VerdictDeny, By: "desktop"})
	expectNoDecision(t, decisions)
	e.desktop.mu.Lock()
	_, kept := e.desktop.handlers[id]
	e.desktop.mu.Unlock()
	if kept {
		t.Error("a closed notification keeps its handler")
	}
}

func TestDesktopInform(t *testing.T) {
	e := newDesktopEnv(t)
	if err := e.desktop.Inform("Task finished", "Tests <pass>"); err != nil {
		t.Fatal(err)
	}
	got := e.server.last(t)
	if got.summary != "Agent: Task finished" || got.body != "Tests &lt;pass&gt;" || len(got.actions) != 0 {
		t.Errorf("inform = %+v", got)
	}
}
