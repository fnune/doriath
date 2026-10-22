package session

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/control"
	"github.com/fnune/doriath/internal/profile"
)

type tlsCertificate = tls.Certificate

const (
	MethodSubmit       = "approval.submit"
	MethodInform       = "inform"
	MethodStatus       = "status"
	MethodRequestWrite = "path.request_write"
	MethodWait         = "approval.wait"
)

// WaitParams names a request by its id, or by what it asks for: a host or
// an absolute path.
type WaitParams struct {
	ID   string `json:"id,omitempty"`
	Host string `json:"host,omitempty"`
	Path string `json:"path,omitempty"`
}

// RequestWriteResult is the decision, or the id of the request that is
// still pending once the wait is over.
type RequestWriteResult struct {
	Decision approval.Decision `json:"decision"`
	Pending  string            `json:"pending,omitempty"`
}

const (
	MethodList       = "approvals.list"
	MethodDecide     = "approvals.decide"
	MethodInfo       = "session.info"
	MethodGrantWrite = "path.grant_write"
)

type RequestWriteParams struct {
	Path string `json:"path"`
	// Reason is the agent's own text, shown to you as such.
	Reason string `json:"reason,omitempty"`
}

type GrantWriteParams struct {
	Path string `json:"path"`
}

// GrantWriteResult tells you how to keep the grant for later sessions.
type GrantWriteResult struct {
	Hint string `json:"hint"`
}

type SubmitParams struct {
	Agent   string `json:"agent"`
	Summary string `json:"summary"`
	Details string `json:"details,omitempty"`
	Note    string `json:"note,omitempty"`
	URL     string `json:"url,omitempty"`
	Scope   string `json:"scope,omitempty"`
	// TimeoutSeconds bounds the wait. Without a decision in time the result
	// has verdict "none".
	TimeoutSeconds int `json:"timeout_seconds"`
}

type InformParams struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

type DecideParams struct {
	ID       string            `json:"id"`
	Decision approval.Decision `json:"decision"`
}

const maxSubmitTimeout = time.Hour

func (s *Session) startBroker(ctx context.Context) error {
	l, err := s.listen(BrokerSocket)
	if err != nil {
		return err
	}
	srv := control.NewServer(map[string]control.Handler{
		MethodSubmit: func(ctx context.Context, raw json.RawMessage) (any, error) {
			p, err := control.Decode[SubmitParams](raw)
			if err != nil {
				return nil, err
			}
			if p.Summary == "" {
				return nil, fmt.Errorf("summary is required")
			}
			timeout := time.Duration(p.TimeoutSeconds) * time.Second
			if timeout <= 0 || timeout > maxSubmitTimeout {
				return nil, fmt.Errorf("timeout_seconds must be between 1 and %d", int(maxSubmitTimeout/time.Second))
			}
			return s.manager.Submit(ctx, approval.Request{
				Session: s.id,
				Profile: s.req.Profile.Name,
				Agent:   p.Agent,
				Kind:    approval.KindTool,
				Summary: p.Summary,
				Details: p.Details,
				Note:    p.Note,
				URL:     p.URL,
				Scope:   "tool " + p.Agent + " " + p.Scope,
			}, timeout)
		},
		MethodStatus: func(context.Context, json.RawMessage) (any, error) {
			return s.status(), nil
		},
		MethodRequestWrite: func(_ context.Context, raw json.RawMessage) (any, error) {
			p, err := control.Decode[RequestWriteParams](raw)
			if err != nil {
				return nil, err
			}
			return s.requestWrite(p.Path, p.Reason)
		},
		MethodWait: func(ctx context.Context, raw json.RawMessage) (any, error) {
			p, err := control.Decode[WaitParams](raw)
			if err != nil {
				return nil, err
			}
			switch {
			case p.Host != "":
				return s.manager.WaitScope(ctx, "host egress "+strings.ToLower(p.Host))
			case p.Path != "":
				return s.manager.WaitScope(ctx, "path write "+filepath.Clean(p.Path))
			}
			return s.manager.Wait(ctx, p.ID)
		},
		MethodInform: func(_ context.Context, raw json.RawMessage) (any, error) {
			p, err := control.Decode[InformParams](raw)
			if err != nil {
				return nil, err
			}
			ok, firstDropped := s.informs.allow(s.deps.Clock.Now())
			if !ok {
				if firstDropped {
					s.log.Write("inform-dropped", p)
				}
				return nil, fmt.Errorf("too many notifications: doriath shows %d at once and one more each %s", informBurst, informEvery)
			}
			s.log.Write("inform", p)
			if s.deps.Informer != nil {
				if err := s.deps.Informer.Inform(p.Title, p.Body); err != nil {
					return nil, err
				}
			}
			return struct{}{}, nil
		},
	})
	go func() { _ = srv.Serve(ctx, l) }()
	return nil
}

func (s *Session) startControl(ctx context.Context) error {
	path := filepath.Join(s.dir, ControlSocket)
	l, err := listenUnix(path)
	if err != nil {
		return err
	}
	s.closers = append(s.closers, func() { _ = l.Close() })
	srv := control.NewServer(map[string]control.Handler{
		MethodList: func(context.Context, json.RawMessage) (any, error) {
			return s.manager.Pending(), nil
		},
		MethodDecide: func(_ context.Context, raw json.RawMessage) (any, error) {
			p, err := control.Decode[DecideParams](raw)
			if err != nil {
				return nil, err
			}
			if p.Decision.By == "" {
				p.Decision.By = "cli"
			}
			return struct{}{}, s.manager.Decide(p.ID, p.Decision)
		},
		MethodStatus: func(context.Context, json.RawMessage) (any, error) {
			return s.status(), nil
		},
		MethodGrantWrite: func(ctx context.Context, raw json.RawMessage) (any, error) {
			p, err := control.Decode[GrantWriteParams](raw)
			if err != nil {
				return nil, err
			}
			if err := s.grantWrite(ctx, p.Path); err != nil {
				return nil, err
			}
			return GrantWriteResult{Hint: s.profileHint(filepath.Clean(p.Path))}, nil
		},
		MethodInfo: func(context.Context, json.RawMessage) (any, error) {
			data, err := os.ReadFile(filepath.Join(s.dir, InfoFile))
			if err != nil {
				return nil, err
			}
			var info Info
			return info, json.Unmarshal(data, &info)
		},
	})
	go func() { _ = srv.Serve(ctx, l) }()
	return nil
}

// Status is what the agent and the person can learn about a running session.
type Status struct {
	Session     string       `json:"session"`
	Profile     string       `json:"profile"`
	Writable    []string     `json:"writable"`
	ReadOnly    []string     `json:"read_only"`
	Hosts       []string     `json:"hosts"`
	Intercepted []StatusHost `json:"intercepted"`
	Ports       []int        `json:"ports"`
	Signing     bool         `json:"signing"`
	Podman      bool         `json:"podman"`
	Pending     int          `json:"pending"`
	Denied      []Denial     `json:"denied"`
}

type StatusHost struct {
	Host       string       `json:"host"`
	Credential bool         `json:"credential"`
	Default    string       `json:"default"`
	Rules      []StatusRule `json:"rules"`
}

type StatusRule struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Action  string `json:"action"`
	Summary string `json:"summary,omitempty"`
}

func (s *Session) status() Status {
	p := s.req.Profile
	st := Status{
		Session: s.id,
		Profile: p.Name,
		Ports:   append(append([]int(nil), p.Egress.Ports...), p.Egress.TCPPorts...),
		Signing: p.SigningKey != "",
		Podman:  p.Podman,
		Pending: len(s.manager.Pending()),
		Denied:  s.egress.Denials(),
	}
	for _, m := range p.Mounts {
		switch m.Mode {
		case profile.ModeWrite:
			st.Writable = append(st.Writable, m.Path)
		case profile.ModeRead:
			st.ReadOnly = append(st.ReadOnly, m.Path)
		}
	}
	for _, c := range p.Caches {
		st.Writable = append(st.Writable, c.Path)
	}
	for _, h := range p.Egress.Allow {
		st.Hosts = append(st.Hosts, string(h))
	}
	for _, h := range p.HTTP {
		sh := StatusHost{Host: string(h.Host), Credential: h.Credential != nil, Default: string(h.Default)}
		for _, r := range h.Rules {
			sh.Rules = append(sh.Rules, StatusRule{Method: r.Method, Path: string(r.Path), Action: string(r.Action), Summary: r.Summary})
		}
		st.Intercepted = append(st.Intercepted, sh)
	}
	return st
}
