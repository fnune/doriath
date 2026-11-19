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
	KindHTTP      Kind = "http"
	KindTool      Kind = "tool"
	KindHost      Kind = "host"
	KindPath      Kind = "path"
	KindRead      Kind = "read"
	KindSecret    Kind = "secret"
	KindEdit      Kind = "edit"
	KindClipboard Kind = "clipboard"
	KindOpen      Kind = "open"
	KindForward   Kind = "forward"
	KindConnect   Kind = "connect"
)

type Answer string

const (
	AnswerOnce        Answer = "once"
	AnswerSession     Answer = "session"
	AnswerDeny        Answer = "deny"
	AnswerDenySession Answer = "deny-session"
)

type Button struct {
	Answer Answer
	Label  string
}

func (k Kind) Buttons() []Button {
	switch k {
	case KindHost, KindPath, KindRead, KindForward, KindConnect:
		return []Button{{AnswerSession, "Allow for this session"}, {AnswerDenySession, "Deny for this session"}, {AnswerDeny, "Deny"}}
	case KindSecret:
		return []Button{{AnswerOnce, "Try again"}, {AnswerDeny, "Dismiss"}}
	}
	return []Button{{AnswerOnce, "Allow once"}, {AnswerSession, "Allow for this session"}, {AnswerDeny, "Deny"}}
}

// Buttons are the answers that the request offers. A request with a
// warning can be allowed once only, so that each new one asks you again.
func (r Request) Buttons() []Button {
	if r.Warning == "" {
		return r.Kind.Buttons()
	}
	return []Button{{AnswerOnce, "Allow once"}, {AnswerDeny, "Deny"}}
}

func (r Request) Offers(a Answer) bool {
	for _, b := range r.Buttons() {
		if b.Answer == a {
			return true
		}
	}
	return false
}

func (k Kind) Offers(a Answer) bool {
	for _, b := range k.Buttons() {
		if b.Answer == a {
			return true
		}
	}
	return false
}

func (a Answer) Decision(by string) (Decision, bool) {
	switch a {
	case AnswerOnce:
		return Decision{Verdict: VerdictAllow, Lasting: LastingOnce, By: by}, true
	case AnswerSession:
		return Decision{Verdict: VerdictAllow, Lasting: LastingSession, By: by}, true
	case AnswerDeny:
		return Decision{Verdict: VerdictDeny, By: by}, true
	case AnswerDenySession:
		return Decision{Verdict: VerdictDeny, Lasting: LastingSession, By: by}, true
	}
	return Decision{}, false
}

func (k Kind) Answered(d Decision) string {
	switch {
	case k == KindSecret && d.Verdict == VerdictAllow:
		return "Tried again"
	case k == KindSecret && d.Verdict == VerdictDeny:
		return "Dismissed"
	case d.Verdict == VerdictAllow && d.Lasting == LastingOnce:
		return "Allowed once"
	case d.Verdict == VerdictAllow && d.Lasting == LastingUntil:
		return "Allowed until " + d.Until.Local().Format("15:04")
	case d.Verdict == VerdictAllow:
		return "Allowed for the session"
	case d.Verdict == VerdictDeny && d.Lasting == LastingSession:
		return "Denied for the session"
	case d.Verdict == VerdictDeny && d.Lasting == LastingUntil:
		return "Denied until " + d.Until.Local().Format("15:04")
	case d.Verdict == VerdictDeny:
		return "Denied"
	}
	return "No answer in time"
}

type Request struct {
	ID       string   `json:"id"`
	Session  string   `json:"session"`
	Profile  string   `json:"profile"`
	Agent    string   `json:"agent,omitempty"`
	Kind     Kind     `json:"kind"`
	Summary  string   `json:"summary"`
	Action   string   `json:"action,omitempty"`
	Facts    []Fact   `json:"facts,omitempty"`
	Commands []string `json:"commands,omitempty"`
	Link     Link     `json:"link,omitzero"`
	Details  string   `json:"details,omitempty"`
	// Warning is doriath's own text on a request that touches a path your
	// machine runs or reads on its own.
	Warning            string    `json:"warning,omitempty"`
	Note               string    `json:"note,omitempty"`
	SessionDescription string    `json:"session_description,omitempty"`
	Keep               string    `json:"keep,omitempty"`
	KeepDeny           string    `json:"keep_deny,omitempty"`
	Command            string    `json:"command,omitempty"`
	URL                string    `json:"url,omitempty"`
	Scope              string    `json:"scope"`
	Created            time.Time `json:"created"`
	Expires            time.Time `json:"expires"`
	// AgentWaits is when the agent stops waiting for the answer. The request
	// stays answerable after that, until Expires.
	AgentWaits time.Time `json:"agent_waits,omitzero"`
}

type Fact struct {
	Label string `json:"label"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

// Link is the page a request is about. Opening it answers nothing.
type Link struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

func (r Request) Title() string {
	if r.Action != "" {
		return r.Action
	}
	return r.Summary
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
		switch d.Lasting {
		case "", LastingOnce, LastingSession:
			return nil
		case LastingUntil:
			if d.Until.IsZero() {
				return errors.New("a deny until a time needs the time")
			}
			return nil
		}
		return fmt.Errorf("lasting %q: want once, session or until", d.Lasting)
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

const ByGrant = "grant"

type Recorder interface {
	Requested(req Request)
	Decided(req Request, d Decision)
}

type IDs interface {
	New() string
}

var ErrUnknownRequest = errors.New("unknown or already decided request")

// MaxPending bounds the requests waiting at once. A flood of them would
// bury the one that matters and invite clicking allow.
const MaxPending = 32

type Manager struct {
	clock    Clock
	notifier Notifier
	recorder Recorder
	ids      IDs

	mu              sync.Mutex
	pending         map[string]*pending
	refusalRecorded bool
	grants          map[string]grant
	history         []Outcome
}

type Outcome struct {
	Request  Request
	Decision Decision
}

type pending struct {
	req      Request
	decision chan Decision

	done    chan struct{}
	result  Decision
	settled chan struct{}
}

func newPending(req Request) *pending {
	return &pending{req: req, decision: make(chan Decision, 1), done: make(chan struct{}), settled: make(chan struct{})}
}

func (p *pending) finish(d Decision) {
	p.result = d
	close(p.done)
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

func (m *Manager) Submit(ctx context.Context, req Request, ttl time.Duration) (Decision, error) {
	return m.submit(ctx, req, ttl, nil, nil)
}

func (m *Manager) submit(ctx context.Context, req Request, ttl time.Duration, registered func(*pending), decided func(Decision)) (Decision, error) {
	now := m.clock.Now()
	m.mu.Lock()
	if g, ok := m.grants[grantKey(req)]; ok && req.Scope != "" {
		if g.forever || now.Before(g.until) {
			m.mu.Unlock()
			d := Decision{Verdict: g.decision.Verdict, Lasting: g.decision.Lasting, Until: g.until, By: ByGrant}
			if d.Verdict == VerdictDeny {
				d.Reason = "the user denied it for this session"
			}
			m.recorder.Decided(req, d)
			return d, nil
		}
		delete(m.grants, grantKey(req))
	}
	if len(m.pending) >= MaxPending {
		record := !m.refusalRecorded
		m.refusalRecorded = true
		m.mu.Unlock()
		d := Decision{Verdict: VerdictDeny, Reason: fmt.Sprintf("%d requests are already waiting for a decision; wait for those first", MaxPending)}
		if record {
			m.recorder.Decided(req, d)
		}
		return d, nil
	}
	m.refusalRecorded = false
	req.ID = m.ids.New()
	for m.pending[req.ID] != nil {
		req.ID = m.ids.New()
	}
	req.Created = now
	req.Expires = now.Add(ttl)
	if req.AgentWaits.IsZero() || req.AgentWaits.After(req.Expires) {
		req.AgentWaits = req.Expires
	}
	p := newPending(req)
	m.pending[req.ID] = p
	m.mu.Unlock()
	if registered != nil {
		registered(p)
	}

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
	if decided != nil && d.Verdict != VerdictNone {
		decided(d)
	}
	<-p.done
	close(p.settled)
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
	p.finish(d)
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
	if p.req.Warning != "" && d.Verdict == VerdictAllow && d.Lasting != LastingOnce {
		m.mu.Unlock()
		return fmt.Errorf("request %s comes with a warning, so you can allow it once only", id)
	}
	delete(m.pending, id)
	if p.req.Scope != "" {
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
	p.finish(d)
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

func (m *Manager) Propose(req Request, ttl time.Duration, decided func(Decision)) {
	go func() { _, _ = m.submit(context.Background(), req, ttl, nil, decided) }()
}

// Hold shows a request, or joins an identical one already pending, and
// waits up to wait for the answer. The request stays pending after that,
// until it is decided or ttl passes, and decided runs when it is decided.
// Hold returns the request's id, for Wait, unless a grant answered at once.
func (m *Manager) Hold(req Request, ttl, wait time.Duration, decided func(Decision)) (Decision, string) {
	waitsUntil := m.clock.Now().Add(wait)
	req.AgentWaits = waitsUntil
	var p *pending
	if req.Scope != "" {
		m.mu.Lock()
		for _, q := range m.pending {
			if grantKey(q.req) == grantKey(req) {
				p = q
				if waitsUntil.After(p.req.AgentWaits) && !waitsUntil.After(p.req.Expires) {
					p.req.AgentWaits = waitsUntil
				}
				break
			}
		}
		m.mu.Unlock()
	}
	if p == nil {
		type started struct {
			p *pending
			d Decision
		}
		ch := make(chan started, 1)
		go func() {
			sent := false
			d, _ := m.submit(context.Background(), req, ttl, func(p *pending) {
				sent = true
				ch <- started{p: p}
			}, decided)
			if !sent {
				ch <- started{d: d}
			}
		}()
		s := <-ch
		if s.p == nil {
			return s.d, ""
		}
		p = s.p
	}
	select {
	case <-p.settled:
		return p.result, p.req.ID
	case <-m.clock.After(wait):
		return Decision{Verdict: VerdictNone, Reason: "still waiting for a decision"}, p.req.ID
	}
}

func (m *Manager) Wait(ctx context.Context, id string) (Decision, error) {
	return m.waitFor(ctx, id, func(r Request) bool { return r.ID == id })
}

func (m *Manager) WaitScope(ctx context.Context, scope string) (Decision, error) {
	return m.waitFor(ctx, scope, func(r Request) bool { return r.Scope == scope })
}

func (m *Manager) waitFor(ctx context.Context, name string, match func(Request) bool) (Decision, error) {
	m.mu.Lock()
	var p *pending
	for _, q := range m.pending {
		if match(q.req) {
			p = q
			break
		}
	}
	if p == nil {
		defer m.mu.Unlock()
		for i := len(m.history) - 1; i >= 0; i-- {
			if match(m.history[i].Request) {
				return m.history[i].Decision, nil
			}
		}
		return Decision{}, fmt.Errorf("request %s: %w", name, ErrUnknownRequest)
	}
	m.mu.Unlock()
	select {
	case <-p.done:
		return p.result, nil
	case <-ctx.Done():
		return Decision{Verdict: VerdictNone, Reason: "stopped waiting"}, nil
	}
}

func grantKey(r Request) string { return string(r.Kind) + "\x00" + r.Scope }
