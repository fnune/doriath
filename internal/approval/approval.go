// Package approval holds requests that need a person's decision, and the
// grants that a decision leaves behind.
package approval

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

type Kind string

const (
	KindHTTP Kind = "http"
	KindTool Kind = "tool"
	// KindRule proposes a change to the profile, drafted from a denial. The
	// agent does not wait for it.
	KindRule Kind = "rule"
	// KindPath asks to make a path writable in the running jail. An allow
	// lasts for the session: a write has no natural "once", and keeping it
	// is an edit to the profile.
	KindPath Kind = "path"
)

type Request struct {
	ID      string    `json:"id"`
	Session string    `json:"session"`
	Profile string    `json:"profile"`
	Agent   string    `json:"agent,omitempty"`
	Kind    Kind      `json:"kind"`
	Summary string    `json:"summary"`
	Details string    `json:"details,omitempty"`
	URL     string    `json:"url,omitempty"`
	Scope   string    `json:"scope"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
}

type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictDeny  Verdict = "deny"
	// VerdictNone means nobody decided before the request expired. Each
	// caller chooses what that means: the proxy denies, a hook falls back to
	// the agent's own prompt.
	VerdictNone Verdict = "none"
)

// Lasting says how long an allow decision holds for requests with the same
// scope.
type Lasting string

const (
	LastingOnce    Lasting = "once"
	LastingSession Lasting = "session"
	LastingUntil   Lasting = "until"
)

type Decision struct {
	Verdict Verdict   `json:"verdict"`
	Lasting Lasting   `json:"lasting,omitempty"`
	Until   time.Time `json:"until,omitzero"`
	By      string    `json:"by,omitempty"`
	Reason  string    `json:"reason,omitempty"`
}

func (d Decision) Validate() error {
	switch d.Verdict {
	case VerdictAllow:
		switch d.Lasting {
		case LastingOnce, LastingSession:
			return nil
		case LastingUntil:
			if d.Until.IsZero() {
				return errors.New("an allow until a time needs the time")
			}
			return nil
		}
		return fmt.Errorf("lasting %q: want once, session or until", d.Lasting)
	case VerdictDeny:
		return nil
	}
	return fmt.Errorf("verdict %q: want allow or deny", d.Verdict)
}

type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

// Notifier shows a request to the person. It can answer through respond, for
// example when they click a button. The returned function withdraws the
// notification once the request is decided some other way.
type Notifier interface {
	Notify(ctx context.Context, req Request, respond func(Decision)) (withdraw func(), err error)
}

type Recorder interface {
	Requested(req Request)
	Decided(req Request, d Decision)
}

type IDs interface {
	New() string
}

var ErrUnknownRequest = errors.New("unknown or already decided request")

type Manager struct {
	clock    Clock
	notifier Notifier
	recorder Recorder
	ids      IDs

	mu      sync.Mutex
	pending map[string]*pending
	grants  map[string]grant
	history []Outcome
}

// Outcome is a decided or expired request, for the end-of-session summary.
type Outcome struct {
	Request  Request
	Decision Decision
}

type pending struct {
	req      Request
	decision chan Decision
}

type grant struct {
	until    time.Time
	forever  bool
	decision Decision
}

func NewManager(clock Clock, notifier Notifier, recorder Recorder, ids IDs) *Manager {
	return &Manager{
		clock:    clock,
		notifier: notifier,
		recorder: recorder,
		ids:      ids,
		pending:  map[string]*pending{},
		grants:   map[string]grant{},
	}
}

// Submit blocks until the request is decided, expires, or ctx ends. An
// existing grant for the same scope answers at once.
func (m *Manager) Submit(ctx context.Context, req Request, ttl time.Duration) (Decision, error) {
	now := m.clock.Now()
	m.mu.Lock()
	if g, ok := m.grants[grantKey(req)]; ok && req.Scope != "" {
		if g.forever || now.Before(g.until) {
			m.mu.Unlock()
			return Decision{Verdict: VerdictAllow, Lasting: g.decision.Lasting, Until: g.until, By: "grant"}, nil
		}
		delete(m.grants, grantKey(req))
	}
	req.ID = m.ids.New()
	req.Created = now
	req.Expires = now.Add(ttl)
	p := &pending{req: req, decision: make(chan Decision, 1)}
	m.pending[req.ID] = p
	m.mu.Unlock()

	m.recorder.Requested(req)
	withdraw, err := m.notifier.Notify(ctx, req, func(d Decision) {
		_ = m.Decide(req.ID, d)
	})
	if err != nil {
		withdraw = func() {}
	}

	var d Decision
	select {
	case d = <-p.decision:
	case <-m.clock.After(ttl):
		d = m.expire(req.ID)
	case <-ctx.Done():
		d = m.expire(req.ID)
		d.Reason = "the request was cancelled"
	}
	withdraw()
	return d, nil
}

func (m *Manager) expire(id string) Decision {
	m.mu.Lock()
	p, ok := m.pending[id]
	delete(m.pending, id)
	m.mu.Unlock()
	if !ok {
		return Decision{Verdict: VerdictNone}
	}
	select {
	case d := <-p.decision:
		return d
	default:
	}
	d := Decision{Verdict: VerdictNone, Reason: "nobody decided before the request expired"}
	m.mu.Lock()
	m.history = append(m.history, Outcome{Request: p.req, Decision: d})
	m.mu.Unlock()
	m.recorder.Decided(p.req, d)
	return d
}

func (m *Manager) Decide(id string, d Decision) error {
	if err := d.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	p, ok := m.pending[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("request %s: %w", id, ErrUnknownRequest)
	}
	delete(m.pending, id)
	if d.Verdict == VerdictAllow && p.req.Scope != "" {
		switch d.Lasting {
		case LastingSession:
			m.grants[grantKey(p.req)] = grant{forever: true, decision: d}
		case LastingUntil:
			m.grants[grantKey(p.req)] = grant{until: d.Until, decision: d}
		}
	}
	m.history = append(m.history, Outcome{Request: p.req, Decision: d})
	m.mu.Unlock()
	m.recorder.Decided(p.req, d)
	p.decision <- d
	return nil
}

func (m *Manager) Pending() []Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Request, 0, len(m.pending))
	for _, p := range m.pending {
		out = append(out, p.req)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

func (m *Manager) History() []Outcome {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Outcome(nil), m.history...)
}

// Propose shows a request without anyone waiting for it, and calls decided
// when the person answers. Requests nobody answers expire quietly.
func (m *Manager) Propose(req Request, ttl time.Duration, decided func(Decision)) {
	go func() {
		d, err := m.Submit(context.Background(), req, ttl)
		if err == nil && d.Verdict != VerdictNone && decided != nil {
			decided(d)
		}
	}()
}

func grantKey(r Request) string { return string(r.Kind) + "\x00" + r.Scope }
