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

	"github.com/fnune/doriath/internal/approval"
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

type desktopEnv struct {
	server  *fakeServer
	desktop *Desktop
	address string
}

func newDesktopEnv(t *testing.T) *desktopEnv {
	t.Helper()
	address := privateBus(t)
	server := startServer(t, address)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", address)
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	d, err := NewDesktop(func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return &desktopEnv{server: server, desktop: d, address: address}
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
	if got.summary != "s1: Run: push the branch" {
		t.Errorf("summary = %q", got.summary)
	}
	for _, want := range []string{"Written by claude, not by doriath.", "<tt>git push origin &lt;main&gt;</tt>", "Profile kitchen, session s1.", "Expires in 1m0s."} {
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

func TestDesktopShowsLinksWithoutOpeningThem(t *testing.T) {
	e := newDesktopEnv(t)
	withLink := request
	withLink.URL = "https://github.com/fnune/app/pull/1"
	_, _, _ = e.notify(t, withLink)
	if got := e.server.last(t); slices.Contains(got.actions, "open") || !strings.Contains(got.body, "Link: "+withLink.URL) {
		t.Errorf("a https link shows in the body, without a button: %v %q", got.actions, got.body)
	}
	unsafe := request
	unsafe.URL = "file:///etc/passwd"
	_, _, _ = e.notify(t, unsafe)
	if got := e.server.last(t); strings.Contains(got.body, "Link:") {
		t.Errorf("a file link does not show: %q", got.body)
	}
}

type fakePage struct{ opened chan [2]string }

func (fakePage) Running() bool { return true }

func (p fakePage) Open(request, activation string) error {
	p.opened <- [2]string{request, activation}
	return nil
}

func TestDesktopAnswersOrOpensThePageWhileItRuns(t *testing.T) {
	e := newDesktopEnv(t)
	page := fakePage{opened: make(chan [2]string, 1)}
	e.desktop.Page = page
	id, decisions, _ := e.notify(t, request)
	got := e.server.last(t)
	if want := append(Actions(request), "default", ""); !slices.Equal(got.actions, want) {
		t.Errorf("actions = %v, want %v", got.actions, want)
	}
	if got.body != Body(request, e.desktop.now()) {
		t.Errorf("body = %q", got.body)
	}

	if err := e.server.conn.Emit(objPath, iface+".ActivationToken", id, "token"); err != nil {
		t.Fatal(err)
	}
	e.server.invoke(t, id, "default")
	select {
	case opened := <-page.opened:
		if opened != [2]string{"s1/r1", "token"} {
			t.Errorf("opened = %v", opened)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a click on the notification did not open the page")
	}
	expectNoDecision(t, decisions)

	e.server.invoke(t, id, "allow-once")
	expectDecision(t, decisions, approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingOnce, By: "desktop"})
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
	if err := e.desktop.Inform("s1", "Task finished", "Tests <pass>"); err != nil {
		t.Fatal(err)
	}
	got := e.server.last(t)
	if got.summary != "Agent in s1: Task finished" || got.body != "Tests &lt;pass&gt;" || len(got.actions) != 0 {
		t.Errorf("inform = %+v", got)
	}
}

func TestALongSummaryKeepsTheSessionInTheTitle(t *testing.T) {
	e := newDesktopEnv(t)
	long := request
	long.Summary = "Allow " + strings.Repeat("a", 200) + ".example.com for profile kitchen?"
	e.notify(t, long)
	if got := e.server.last(t).summary; !strings.HasPrefix(got, "s1: ") {
		t.Errorf("summary = %q", got)
	}
}
