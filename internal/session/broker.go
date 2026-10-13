package session

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fnune/girdle/internal/approval"
	"github.com/fnune/girdle/internal/control"
)

type tlsCertificate = tls.Certificate

// Methods on the broker socket, which the jail can reach. They can ask for
// decisions but never make them.
const (
	MethodSubmit = "approval.submit"
	MethodInform = "inform"
)

// Methods on the control socket, which only the host can reach.
const (
	MethodList   = "approvals.list"
	MethodDecide = "approvals.decide"
	MethodInfo   = "session.info"
)

type SubmitParams struct {
	Agent   string `json:"agent"`
	Summary string `json:"summary"`
	Details string `json:"details,omitempty"`
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
				URL:     p.URL,
				Scope:   p.Scope,
			}, timeout)
		},
		MethodInform: func(_ context.Context, raw json.RawMessage) (any, error) {
			p, err := control.Decode[InformParams](raw)
			if err != nil {
				return nil, err
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
