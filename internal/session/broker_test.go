package session

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/control"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/proxy"
)

func TestStatusDescribesTheLiveSession(t *testing.T) {
	s := newTestSession(t, &answering{})
	s.deps.HostWait = 0
	s.req.Profile = &profile.Profile{
		Name: "work",
		Mounts: []profile.Mount{
			{Path: "/w", Mode: profile.ModeWrite},
			{Path: "/r", Mode: profile.ModeRead},
			{Path: "/r/.env", Mode: profile.ModeHide},
		},
		Caches:     []profile.Cache{{Path: "/c"}},
		Egress:     profile.Egress{Allow: []profile.HostPattern{"example.com"}, Ports: []int{3000}, TCPPorts: []int{5432}},
		SigningKey: "agent-key",
		HTTP: []profile.HTTPHost{{
			Host:       "api.github.com",
			Credential: &profile.Credential{Secret: "github"},
			Default:    profile.ActionAllow,
			Rules:      []profile.Rule{{Method: "POST", Path: "/repos/*/*/releases", Action: profile.ActionApprove, Summary: "Create a release"}},
		}},
	}
	s.egress.Egress(proxy.Event{Kind: "denied", Host: "example.org", Reason: "host not in the profile"})
	s.HoldHost(context.Background(), "drafted.example", "")

	st := s.status()
	if st.Session != "s1" || st.Profile != "work" || !st.Signing || st.Podman || st.Pending != 1 {
		t.Errorf("status = %+v", st)
	}
	for name, got := range map[string][]string{"writable": st.Writable, "read-only": st.ReadOnly, "hosts": st.Hosts} {
		want := map[string][]string{"writable": {"/w", "/c"}, "read-only": {"/r"}, "hosts": {"example.com"}}[name]
		if !slices.Equal(got, want) {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	if !slices.Equal(st.Ports, []int{3000, 5432}) {
		t.Errorf("ports = %v", st.Ports)
	}
	want := StatusHost{Host: "api.github.com", Credential: true, Default: "allow", Rules: []StatusRule{{Method: "POST", Path: "/repos/*/*/releases", Action: "approve", Summary: "Create a release"}}}
	if len(st.Intercepted) != 1 || st.Intercepted[0].Host != want.Host || !st.Intercepted[0].Credential || st.Intercepted[0].Default != want.Default || !slices.Equal(st.Intercepted[0].Rules, want.Rules) {
		t.Errorf("intercepted = %+v", st.Intercepted)
	}
	if len(st.Denied) != 1 || st.Denied[0].Host != "example.org" {
		t.Errorf("denied = %+v", st.Denied)
	}
}

type informer struct{ titles []string }

func (i *informer) Inform(title, _ string) error {
	i.titles = append(i.titles, title)
	return nil
}

// brokerSession serves the broker and control sockets of a session that
// runs no jail, in a directory short enough for a socket path. Deps are
// settled before the servers start, as in a real session.
func brokerSession(t *testing.T, notifier approval.Notifier, deps ...func(*Deps)) (*testSession, string, string) {
	t.Helper()
	s := newTestSession(t, notifier)
	for _, set := range deps {
		set(&s.deps)
	}
	dir, err := os.MkdirTemp("", "gs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	s.dir, s.jailDir = dir, filepath.Join(dir, "jail")
	mkdirAll(t, s.jailDir)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Cleanup(s.cleanup)
	if err := s.startBroker(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.startControl(ctx); err != nil {
		t.Fatal(err)
	}
	return s, filepath.Join(s.jailDir, BrokerSocket), filepath.Join(dir, ControlSocket)
}

func TestBrokerRefusesSubmissionsItCannotShow(t *testing.T) {
	_, broker, _ := brokerSession(t, &answering{})
	for _, c := range []struct {
		name    string
		params  SubmitParams
		refusal string
	}{
		{"no summary", SubmitParams{Agent: "claude", TimeoutSeconds: 10}, "summary is required"},
		{"no timeout", SubmitParams{Summary: "Run tests"}, "timeout_seconds must be between 1 and 3600"},
		{"a timeout over an hour", SubmitParams{Summary: "Run tests", TimeoutSeconds: 3601}, "timeout_seconds must be between 1 and 3600"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := control.Call(context.Background(), broker, MethodSubmit, c.params, nil)
			if err == nil || !strings.Contains(err.Error(), c.refusal) {
				t.Fatalf("err = %v, want %q", err, c.refusal)
			}
		})
	}
}

func TestBrokerSubmitsAToolRequestScopedToTheAgent(t *testing.T) {
	notifier := allowing()
	notifier.seen = make(chan approval.Request, 1)
	_, broker, _ := brokerSession(t, notifier)
	var d approval.Decision
	if err := control.Call(context.Background(), broker, MethodSubmit, SubmitParams{Agent: "claude", Summary: "Run: make", Scope: "Bash make", TimeoutSeconds: 10}, &d); err != nil {
		t.Fatal(err)
	}
	if d.Verdict != approval.VerdictAllow {
		t.Errorf("decision = %+v", d)
	}
	if req := <-notifier.seen; req.Kind != approval.KindTool || req.Scope != "tool claude Bash make" || req.Agent != "claude" || req.Session != "s1" {
		t.Errorf("request = %+v", req)
	}
}

func TestBrokerWaitsForAHostByItsLowercaseName(t *testing.T) {
	s, broker, _ := brokerSession(t, denying())
	s.HoldHost(context.Background(), "drafted.example", "")
	var d approval.Decision
	if err := control.Call(context.Background(), broker, MethodWait, WaitParams{Host: "Drafted.Example"}, &d); err != nil {
		t.Fatal(err)
	}
	if d.Verdict != approval.VerdictDeny {
		t.Errorf("decision = %+v", d)
	}
}

func TestBrokerPassesMessagesToTheInformerAndTheAuditLog(t *testing.T) {
	inf := &informer{}
	s, broker, _ := brokerSession(t, nil, func(d *Deps) { d.Informer = inf })
	if err := control.Call(context.Background(), broker, MethodInform, InformParams{Title: "Tests pass", Body: "all 12"}, nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(inf.titles, []string{"Tests pass"}) || !strings.Contains(s.audit.String(), `"inform"`) {
		t.Errorf("titles = %v, audit:\n%s", inf.titles, s.audit)
	}
}

// The jail reaches the broker socket, so the broker must not offer what
// only you may do.
func TestBrokerCannotDecideOrGrant(t *testing.T) {
	_, broker, _ := brokerSession(t, nil)
	for _, method := range []string{MethodDecide, MethodList, MethodGrantWrite, MethodInfo} {
		if err := control.Call(context.Background(), broker, method, struct{}{}, nil); err == nil {
			t.Errorf("the broker answers %s", method)
		}
	}
}

func TestControlDecidesAsTheCLIUnlessToldOtherwise(t *testing.T) {
	s, _, ctl := brokerSession(t, &answering{}, func(d *Deps) { d.HostWait = 0 })
	_, id := s.HoldHost(context.Background(), "drafted.example", "")
	var pending []approval.Request
	if err := control.Call(context.Background(), ctl, MethodList, struct{}{}, &pending); err != nil || len(pending) != 1 || pending[0].ID != id {
		t.Fatalf("pending = %+v, %v", pending, err)
	}
	if err := control.Call(context.Background(), ctl, MethodDecide, DecideParams{ID: id, Decision: approval.Decision{Verdict: approval.VerdictDeny}}, nil); err != nil {
		t.Fatal(err)
	}
	if h := s.manager.History(); len(h) != 1 || h[0].Decision.By != "cli" {
		t.Errorf("history = %+v", h)
	}
}

func TestControlGrantsWriteAndReturnsTheProfileLines(t *testing.T) {
	s, _, ctl := brokerSession(t, nil)
	s.peers.setInit(4242)
	videos := filepath.Join(s.home, "videos")
	var res GrantWriteResult
	if err := control.Call(context.Background(), ctl, MethodGrantWrite, GrantWriteParams{Path: videos + "/"}, &res); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Hint, `path = "`+videos+`"`) || len(s.promoted.requests) != 1 {
		t.Errorf("hint = %q, promotions = %+v", res.Hint, s.promoted.requests)
	}
	if err := control.Call(context.Background(), ctl, MethodGrantWrite, GrantWriteParams{Path: "/etc"}, nil); err == nil {
		t.Error("a refused grant reported success")
	}
}

func TestControlReportsTheSessionInfo(t *testing.T) {
	s, _, ctl := brokerSession(t, nil)
	s.req.Cwd, s.req.Command = "/w", []string{"claude"}
	if err := s.writeInfo(); err != nil {
		t.Fatal(err)
	}
	var info Info
	if err := control.Call(context.Background(), ctl, MethodInfo, struct{}{}, &info); err != nil {
		t.Fatal(err)
	}
	if info.ID != "s1" || info.Profile != "p" || info.Cwd != "/w" || !slices.Equal(info.Command, []string{"claude"}) || info.PID != os.Getpid() || !info.Started.Equal(stillClock{}.Now()) {
		t.Errorf("info = %+v", info)
	}
}
