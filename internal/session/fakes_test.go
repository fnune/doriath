package session

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"testing/fstest"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/audit"
	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/modules"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/promote"
	"github.com/fnune/doriath/internal/secret"
)

// stillClock never lets a request expire, and lets a wait of zero end at
// once, so a test decides whether a request is answered or left pending.
type stillClock struct{}

func (stillClock) Now() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }

func (stillClock) After(d time.Duration) <-chan time.Time {
	if d > 0 {
		return nil
	}
	ch := make(chan time.Time, 1)
	ch <- time.Time{}
	return ch
}

// answering is a person who answers every request with decision, or
// never answers when it is nil.
type answering struct {
	decision *approval.Decision
	seen     chan approval.Request
}

func (a *answering) Notify(_ context.Context, req approval.Request, respond func(approval.Decision)) (func(), error) {
	if a.seen != nil {
		a.seen <- req
	}
	if a.decision != nil {
		respond(*a.decision)
	}
	return func() {}, nil
}

func allowing() *answering {
	return &answering{decision: &approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession, By: "test"}}
}

func denying() *answering {
	return &answering{decision: &approval.Decision{Verdict: approval.VerdictDeny, By: "test"}}
}

type promotions struct {
	requests []promote.Request
	reads    []promote.Request
	err      error
}

func (p *promotions) Writable(_ context.Context, r promote.Request) error {
	p.requests = append(p.requests, r)
	return p.err
}

func (p *promotions) Readable(_ context.Context, r promote.Request) error {
	p.reads = append(p.reads, r)
	return p.err
}

// testSession is a session that has not started a jail: its home is a
// fresh directory, and paths under it can become writable.
type testSession struct {
	*Session
	home     string
	audit    *bytes.Buffer
	promoted *promotions
}

func newTestSession(t *testing.T, notifier approval.Notifier) *testSession {
	t.Helper()
	home := realTempDir(t)
	doriath := filepath.Join(home, ".doriath")
	paths := config.Paths{
		Home:    home,
		Config:  filepath.Join(doriath, "config"),
		State:   filepath.Join(doriath, "state"),
		Cache:   filepath.Join(doriath, "cache"),
		Runtime: filepath.Join(doriath, "run"),
	}
	var buf bytes.Buffer
	log := audit.New(&buf, stillClock{}.Now, "s1", "p")
	promoted := &promotions{}
	s := &Session{
		deps:             Deps{Paths: paths, Secrets: secret.NewConfigured(nil, nil, nil), Clock: stillClock{}, HostWait: time.Hour, Promote: promoted.Writable, Read: promoted.Readable},
		req:              Request{Profile: &profile.Profile{Name: "p", PathRules: builtinRules(t, home)}},
		id:               "s1",
		log:              log,
		peers:            newHostPeers(""),
		entry:            Entry{Writable: []string{home}},
		manager:          approval.NewManager(stillClock{}, notifier, log, randomIDs{}),
		listings:         newListingCache(),
		links:            newLinkKeeper(func(string, string) {}),
		dismissedSecrets: map[string]bool{},
		informs:          newRateLimit(informBurst),
		describes:        newRateLimit(describeBurst),
	}
	s.egress = newEgressLog(log)
	s.policy = newLivePolicy(s.req.Profile, false)
	return &testSession{Session: s, home: home, audit: &buf, promoted: promoted}
}

func builtinRules(t *testing.T, home string) profile.PathRules {
	t.Helper()
	l := &profile.Loader{Profiles: fstest.MapFS{"p.toml": {}}, Modules: []fs.FS{modules.FS}, Home: home, Builtins: modules.Builtins}
	p, err := l.Load("p")
	if err != nil {
		t.Fatal(err)
	}
	p.PathRules.Warn = slices.DeleteFunc(p.PathRules.Warn, func(w profile.PathWarning) bool { return within(home, w.Path) })
	return p.PathRules
}

// realTempDir resolves the temporary directory, because doriath refuses
// paths that go through a symlink and TMPDIR may be one.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func mkdirAll(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

// waitFor polls for the effect of a callback that runs on a goroutine of
// its own and signals nothing when it is done.
func waitFor(t *testing.T, done func() bool, failure string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatal(failure)
		}
		time.Sleep(time.Millisecond)
	}
}
