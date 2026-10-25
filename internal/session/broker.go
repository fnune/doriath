package session

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/fnune/doriath/internal/agents"
	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/control"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/secret"
)

type tlsCertificate = tls.Certificate

const (
	MethodSubmit        = "approval.submit"
	MethodInform        = "inform"
	MethodStatus        = "status"
	MethodRequestWrite  = "path.request_write"
	MethodRequestRead   = "path.request_read"
	MethodRequestModule = "module.request"
	MethodRequestHost   = "host.request"
	MethodRequestOpen   = "link.open"
	MethodRequestPort   = "port.forward"
	MethodWait          = "approval.wait"
)

// WaitParams names a request by its id, or by what it asks for: a host or
// an absolute path.
type WaitParams struct {
	ID   string `json:"id,omitempty"`
	Host string `json:"host,omitempty"`
	Path string `json:"path,omitempty"`
}

// RequestResult is the decision, or the id of the request that is
// still pending once the wait is over.
type RequestResult struct {
	Decision approval.Decision `json:"decision"`
	Pending  string            `json:"pending,omitempty"`
}

const (
	MethodList    = "approvals.list"
	MethodDecide  = "approvals.decide"
	MethodInfo    = "session.info"
	MethodProvide = "secret.provide"
)

type ProvideParams struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type RequestWriteParams struct {
	Path string `json:"path"`
	// Reason is the agent's own text, shown to you as such.
	Reason string `json:"reason,omitempty"`
}

// SubmitParams is a tool call from an agent's hook. The session derives
// what you see and what an allow covers from the tool and its input.
type SubmitParams struct {
	Agent string          `json:"agent"`
	Tool  string          `json:"tool"`
	Input json.RawMessage `json:"input,omitempty"`
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
			if AdapterNamed(p.Agent) == nil {
				return nil, fmt.Errorf("unknown agent %q", p.Agent)
			}
			if p.Tool == "" || strings.ContainsFunc(p.Tool, unicode.IsSpace) {
				return nil, fmt.Errorf("tool must be a name without spaces")
			}
			timeout := time.Duration(p.TimeoutSeconds) * time.Second
			if timeout <= 0 || timeout > maxSubmitTimeout {
				return nil, fmt.Errorf("timeout_seconds must be between 1 and %d", int(maxSubmitTimeout/time.Second))
			}
			call := agents.PermissionRequest{ToolName: p.Tool, ToolInput: p.Input}
			summary, note, details := call.Describe()
			return s.manager.Submit(ctx, approval.Request{
				Session: s.id,
				Profile: s.req.Profile.Name,
				Agent:   p.Agent,
				Kind:    approval.KindTool,
				Summary: summary,
				Details: details,
				Note:    note,
				Scope:   "tool " + p.Agent + " " + call.Scope(),
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
		MethodRequestRead: func(_ context.Context, raw json.RawMessage) (any, error) {
			p, err := control.Decode[RequestReadParams](raw)
			if err != nil {
				return nil, err
			}
			return s.requestRead(p.Path, p.Reason)
		},
		MethodRequestModule: func(_ context.Context, raw json.RawMessage) (any, error) {
			p, err := control.Decode[RequestModuleParams](raw)
			if err != nil {
				return nil, err
			}
			return s.requestModule(p.Module, p.Path, p.Reason)
		},
		MethodRequestOpen: func(_ context.Context, raw json.RawMessage) (any, error) {
			p, err := control.Decode[RequestOpenParams](raw)
			if err != nil {
				return nil, err
			}
			return s.requestOpen(p.URL, p.Reason)
		},
		MethodRequestPort: func(_ context.Context, raw json.RawMessage) (any, error) {
			p, err := control.Decode[RequestForwardParams](raw)
			if err != nil {
				return nil, err
			}
			return s.requestForward(p.HostPort, p.JailPort, p.Reason)
		},
		MethodRequestHost: func(_ context.Context, raw json.RawMessage) (any, error) {
			p, err := control.Decode[RequestHostParams](raw)
			if err != nil {
				return nil, err
			}
			return s.requestHost(p.Host, p.Reason)
		},
		MethodRequestEdit: func(_ context.Context, raw json.RawMessage) (any, error) {
			p, err := control.Decode[RequestEditParams](raw)
			if err != nil {
				return nil, err
			}
			return s.requestEdit(p.Path, p.Content, p.Reason)
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
				return s.manager.WaitScope(ctx, s.pathScope(filepath.Clean(p.Path)))
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
				if err := s.deps.Informer.Inform(s.id, p.Title, p.Body); err != nil {
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
			return s.hostStatus(), nil
		},

		MethodProvide: func(_ context.Context, raw json.RawMessage) (any, error) {
			p, err := control.Decode[ProvideParams](raw)
			if err != nil {
				return nil, err
			}
			return struct{}{}, s.provide(p.Name, secret.NewValue([]byte(p.Value)))
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

func (s *Session) pathScope(path string) string {
	pending := s.manager.Pending()
	for _, r := range pending {
		if r.Scope == "path read "+path {
			return r.Scope
		}
		if rest, ok := strings.CutPrefix(r.Scope, "module "); ok && strings.HasSuffix(rest, " "+path) {
			return r.Scope
		}
	}
	return "path write " + path
}

// Status is what the agent and the person can learn about a running session.
type Status struct {
	Session string `json:"session"`
	Profile string `json:"profile"`
	// Modules are the modules that the agent can ask to use in another
	// repository.
	Modules     []string        `json:"modules,omitempty"`
	Writable    []string        `json:"writable"`
	ReadOnly    []string        `json:"read_only"`
	Hosts       []string        `json:"hosts"`
	Intercepted []StatusHost    `json:"intercepted"`
	Ports       []int           `json:"ports"`
	Forwards    []StatusForward `json:"forwards,omitempty"`
	Signing     bool            `json:"signing"`
	Podman      bool            `json:"podman"`
	Pending     int             `json:"pending"`
	Denied      []Denial        `json:"denied"`
	Secrets     []string        `json:"secrets,omitempty"`
	Unavailable []Missing       `json:"unavailable,omitempty"`
}

// Missing is a secret that doriath could not read, and what fails without
// it.
type Missing struct {
	Secret string   `json:"secret"`
	Error  string   `json:"error"`
	Users  []string `json:"users"`
}

// StatusForward is a port of your machine that reaches a port in the jail.
type StatusForward struct {
	Host int `json:"host"`
	Jail int `json:"jail"`
}

type StatusHost struct {
	Host       string       `json:"host"`
	Credential bool         `json:"credential"`
	Default    string       `json:"default"`
	Rules      []StatusRule `json:"rules"`
}

type StatusRule struct {
	Method  string   `json:"method"`
	Path    string   `json:"path"`
	Action  string   `json:"action"`
	Summary string   `json:"summary,omitempty"`
	Refs    []string `json:"refs,omitempty"`
}

func (s *Session) status() Status {
	p := s.req.Profile
	st := Status{
		Session:  s.id,
		Profile:  p.Name,
		Ports:    append(append([]int(nil), p.Egress.Ports...), p.Egress.TCPPorts...),
		Forwards: s.lastingForwards(),
		Signing:  p.SigningKey != "",
		Podman:   p.Podman,
		Pending:  len(s.manager.Pending()),
		Denied:   s.egress.Denials(),
	}
	if s.unresolved != nil {
		st.Modules = s.unresolved.RepositoryModules()
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
			rule := StatusRule{Method: r.Method, Path: string(r.Path), Action: string(r.Action), Summary: r.Summary}
			for _, ref := range r.Refs {
				rule.Refs = append(rule.Refs, string(ref))
			}
			sh.Rules = append(sh.Rules, rule)
		}
		st.Intercepted = append(st.Intercepted, sh)
	}
	secrets := s.secretsStatus()
	st.Secrets, st.Unavailable = secrets.Secrets, secrets.Unavailable
	return st
}

func (s *Session) provide(name string, v secret.Value) error {
	if name == s.req.Profile.SigningKey {
		return fmt.Errorf("secret %q is the signing key, which the session reads when it starts", name)
	}
	if err := s.deps.Secrets.Provide(name, v); err != nil {
		return err
	}
	s.log.Write("secret-provided", map[string]string{"secret": name})
	return nil
}

func (s *Session) hostStatus() Status {
	st := s.status()
	unavailable := s.deps.Secrets.Unavailable()
	for i, m := range st.Unavailable {
		if err, ok := unavailable[m.Secret]; ok {
			st.Unavailable[i].Error = secret.Explained(err).Error()
		}
	}
	return st
}

func (s *Session) secretsStatus() Status {
	p := s.req.Profile
	st := Status{Secrets: slices.Sorted(maps.Keys(p.Secrets))}
	unavailable := s.deps.Secrets.Unavailable()
	for _, name := range slices.Sorted(maps.Keys(unavailable)) {
		st.Unavailable = append(st.Unavailable, Missing{Secret: name, Error: unavailable[name].Error(), Users: secretUsers(p, name)})
	}
	return st
}
