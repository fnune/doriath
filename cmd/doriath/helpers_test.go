package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/control"
	"github.com/fnune/doriath/internal/notify"
	"github.com/fnune/doriath/internal/session"
)

// testPaths points every directory doriath reads at a fresh temporary one.
// The runtime directory is short because unix socket paths are limited to
// 108 bytes.
func testPaths(t *testing.T) config.Paths {
	t.Helper()
	home := t.TempDir()
	runtime, err := os.MkdirTemp("", "gd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtime) })
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	t.Setenv("XDG_RUNTIME_DIR", runtime)
	t.Setenv("DORIATH_CONFIG_DIR", filepath.Join(home, "config"))
	t.Setenv("DORIATH_BROKER", "")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+filepath.Join(runtime, "no-bus"))
	p, err := paths()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func writeProfile(t *testing.T, p config.Paths, name, body string) {
	t.Helper()
	if err := os.MkdirAll(p.Profiles(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.Profiles(), name+".toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// requestedIDs tells a test when a request is pending.
type requestedIDs chan string

func (r requestedIDs) Requested(req approval.Request)            { r <- req.ID }
func (requestedIDs) Decided(approval.Request, approval.Decision) {}

type prefixIDs struct {
	mu     sync.Mutex
	prefix string
	n      int
}

func (p *prefixIDs) New() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	return fmt.Sprintf("%s-r%d", p.prefix, p.n)
}

// fakeSession serves a session's control socket in-process and writes the
// info file the way a session does, so the CLI finds it.
type fakeSession struct {
	id        string
	profile   string
	manager   *approval.Manager
	requested requestedIDs
	status    session.Status
	mu        sync.Mutex
	granted   []string
	provided  map[string]string
}

func startSession(t *testing.T, p config.Paths, id, profile string, started time.Time) *fakeSession {
	t.Helper()
	requested := make(requestedIDs, 1)
	s := &fakeSession{
		id:        id,
		profile:   profile,
		manager:   approval.NewManager(realClock{}, notify.None{}, requested, &prefixIDs{prefix: id}),
		requested: requested,
		status:    session.Status{Session: id, Profile: profile},
	}
	dir := filepath.Join(p.Sessions(), id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	info := session.Info{ID: id, Profile: profile, Cwd: "/work", Command: []string{"claude"}, PID: os.Getpid(), Started: started}
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, session.InfoFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", filepath.Join(dir, session.ControlSocket))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	srv := control.NewServer(map[string]control.Handler{
		session.MethodList: func(context.Context, json.RawMessage) (any, error) {
			return s.manager.Pending(), nil
		},
		session.MethodDecide: func(_ context.Context, raw json.RawMessage) (any, error) {
			params, err := control.Decode[session.DecideParams](raw)
			if err != nil {
				return nil, err
			}
			return struct{}{}, s.manager.Decide(params.ID, params.Decision)
		},
		session.MethodStatus: func(context.Context, json.RawMessage) (any, error) {
			return s.status, nil
		},
		session.MethodGrantWrite: func(_ context.Context, raw json.RawMessage) (any, error) {
			params, err := control.Decode[session.GrantWriteParams](raw)
			if err != nil {
				return nil, err
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			s.granted = append(s.granted, params.Path)
			return session.GrantWriteResult{Hint: "add it to the profile to keep it"}, nil
		},
		session.MethodProvide: func(_ context.Context, raw json.RawMessage) (any, error) {
			params, err := control.Decode[session.ProvideParams](raw)
			if err != nil {
				return nil, err
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.provided == nil {
				s.provided = map[string]string{}
			}
			s.provided[params.Name] = params.Value
			return struct{}{}, nil
		},
	})
	go func() { _ = srv.Serve(context.Background(), l) }()
	return s
}

// submit asks for a decision in the background and waits until the request
// is pending.
func (s *fakeSession) submit(t *testing.T, summary, details string) (string, <-chan approval.Decision) {
	t.Helper()
	out := make(chan approval.Decision, 1)
	go func() {
		d, _ := s.manager.Submit(context.Background(), approval.Request{
			Session: s.id, Profile: s.profile, Kind: approval.KindTool, Summary: summary, Details: details, Scope: "tool " + summary,
		}, time.Minute)
		out <- d
	}()
	select {
	case id := <-s.requested:
		return id, out
	case <-time.After(5 * time.Second):
		t.Fatal("request never became pending")
		return "", nil
	}
}

func receive(t *testing.T, ch <-chan approval.Decision) approval.Decision {
	t.Helper()
	select {
	case d := <-ch:
		return d
	case <-time.After(5 * time.Second):
		t.Fatal("no decision reached the request")
		return approval.Decision{}
	}
}

// fakeBroker stands in for the broker socket a session offers the jail.
type fakeBroker struct {
	mu       sync.Mutex
	submits  []session.SubmitParams
	informs  []session.InformParams
	writes   []session.RequestWriteParams
	reads    []session.RequestReadParams
	hosts    []session.RequestHostParams
	opens    []session.RequestOpenParams
	edits    []session.RequestEditParams
	waits    []session.WaitParams
	decision approval.Decision
	pending  string
	fail     error
	status   session.Status
}

func startBroker(t *testing.T) *fakeBroker {
	t.Helper()
	b := &fakeBroker{}
	dir, err := os.MkdirTemp("", "gb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "broker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	srv := control.NewServer(map[string]control.Handler{
		session.MethodSubmit: func(_ context.Context, raw json.RawMessage) (any, error) {
			params, err := control.Decode[session.SubmitParams](raw)
			if err != nil {
				return nil, err
			}
			b.mu.Lock()
			defer b.mu.Unlock()
			b.submits = append(b.submits, params)
			if b.fail != nil {
				return nil, b.fail
			}
			return b.decision, nil
		},
		session.MethodInform: func(_ context.Context, raw json.RawMessage) (any, error) {
			params, err := control.Decode[session.InformParams](raw)
			if err != nil {
				return nil, err
			}
			b.mu.Lock()
			defer b.mu.Unlock()
			b.informs = append(b.informs, params)
			return struct{}{}, nil
		},
		session.MethodStatus: func(context.Context, json.RawMessage) (any, error) {
			b.mu.Lock()
			defer b.mu.Unlock()
			return b.status, nil
		},
		session.MethodRequestWrite: func(_ context.Context, raw json.RawMessage) (any, error) {
			params, err := control.Decode[session.RequestWriteParams](raw)
			if err != nil {
				return nil, err
			}
			b.mu.Lock()
			defer b.mu.Unlock()
			b.writes = append(b.writes, params)
			if b.fail != nil {
				return nil, b.fail
			}
			return session.RequestResult{Decision: b.decision, Pending: b.pending}, nil
		},
		session.MethodRequestOpen: func(_ context.Context, raw json.RawMessage) (any, error) {
			params, err := control.Decode[session.RequestOpenParams](raw)
			if err != nil {
				return nil, err
			}
			b.mu.Lock()
			defer b.mu.Unlock()
			b.opens = append(b.opens, params)
			return session.RequestResult{Decision: b.decision, Pending: b.pending}, nil
		},
		session.MethodRequestHost: func(_ context.Context, raw json.RawMessage) (any, error) {
			params, err := control.Decode[session.RequestHostParams](raw)
			if err != nil {
				return nil, err
			}
			b.mu.Lock()
			defer b.mu.Unlock()
			b.hosts = append(b.hosts, params)
			return session.RequestResult{Decision: b.decision, Pending: b.pending}, nil
		},
		session.MethodRequestRead: func(_ context.Context, raw json.RawMessage) (any, error) {
			params, err := control.Decode[session.RequestReadParams](raw)
			if err != nil {
				return nil, err
			}
			b.mu.Lock()
			defer b.mu.Unlock()
			b.reads = append(b.reads, params)
			if b.fail != nil {
				return nil, b.fail
			}
			return session.RequestResult{Decision: b.decision, Pending: b.pending}, nil
		},
		session.MethodRequestEdit: func(_ context.Context, raw json.RawMessage) (any, error) {
			params, err := control.Decode[session.RequestEditParams](raw)
			if err != nil {
				return nil, err
			}
			b.mu.Lock()
			defer b.mu.Unlock()
			b.edits = append(b.edits, params)
			if b.fail != nil {
				return nil, b.fail
			}
			if b.decision.Verdict == approval.VerdictAllow {
				if err := os.WriteFile(params.Path, []byte(params.Content), 0o644); err != nil {
					return nil, err
				}
			}
			return session.RequestEditResult{Decision: b.decision, Pending: b.pending, Changes: "changed"}, nil
		},
		session.MethodWait: func(_ context.Context, raw json.RawMessage) (any, error) {
			params, err := control.Decode[session.WaitParams](raw)
			if err != nil {
				return nil, err
			}
			b.mu.Lock()
			defer b.mu.Unlock()
			b.waits = append(b.waits, params)
			if b.fail != nil {
				return nil, b.fail
			}
			return b.decision, nil
		},
	})
	go func() { _ = srv.Serve(context.Background(), l) }()
	t.Setenv("DORIATH_BROKER", sock)
	return b
}

func (b *fakeBroker) set(d approval.Decision, fail error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.decision, b.fail = d, fail
}

func (b *fakeBroker) setStatus(st session.Status) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.status = st
}

func (b *fakeBroker) lastSubmit(t *testing.T) session.SubmitParams {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.submits) == 0 {
		t.Fatal("the hook submitted nothing")
	}
	return b.submits[len(b.submits)-1]
}

func hook(t *testing.T, event, input string, flags ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := cmdHook(append([]string{"claude", event}, flags...), bytes.NewBufferString(input), &out)
	return out.String(), err
}

func (s *fakeSession) grants() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.granted)
}

func (b *fakeBroker) setPending(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pending = id
}

func (b *fakeBroker) sentWrites() []session.RequestWriteParams {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.writes)
}

func (b *fakeBroker) sentWaits() []session.WaitParams {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.waits)
}

// stepClock lets a test see each wait and decide when it ends.
type stepClock struct {
	now   time.Time
	waits chan chan time.Time
}

func newStepClock(now time.Time) *stepClock {
	return &stepClock{now: now, waits: make(chan chan time.Time)}
}

func (c *stepClock) Now() time.Time { return c.now }

func (c *stepClock) After(time.Duration) <-chan time.Time {
	tick := make(chan time.Time, 1)
	c.waits <- tick
	return tick
}

// waiting blocks until the code under test waits on the clock.
func (c *stepClock) waiting(t *testing.T) chan<- time.Time {
	t.Helper()
	select {
	case tick := <-c.waits:
		return tick
	case <-time.After(5 * time.Second):
		t.Fatal("nothing waited on the clock")
		return nil
	}
}
