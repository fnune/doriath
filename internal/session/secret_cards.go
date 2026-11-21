package session

import (
	"context"
	"fmt"
	"strings"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/cli"
	"github.com/fnune/doriath/internal/secret"
)

type carding struct{ s *Session }

func (c carding) Get(ctx context.Context, name string) (secret.Value, error) {
	v, err := c.s.deps.Secrets.Get(ctx, name)
	if err == nil {
		return v, nil
	}
	if id := c.s.secretCard(name, err); id != "" {
		return v, fmt.Errorf("%w. doriath asked the user to fix it on the approvals page. To wait for the answer, run %s", err, cli.Code(cli.Line("request", "wait", id)))
	}
	return v, err
}

func (s *Session) secretCard(name string, cause error) string {
	s.mu.Lock()
	dismissed := s.dismissedSecrets[name]
	s.mu.Unlock()
	if dismissed {
		return ""
	}
	p := s.req.Profile
	command := cli.Line("secrets", "provide", "--session", s.id, name)
	if b := p.Secrets[name]; b.OAuth != nil || b.Keyring {
		command = cli.Line("profiles", "login", p.LoginProfile(name), name)
	}
	req := approval.Request{
		Session: s.id,
		Profile: p.Name,
		Kind:    approval.KindSecret,
		Summary: "Secret " + name + " is unavailable",
		Action:  "Secret unavailable",
		Facts:   []approval.Fact{{Label: "Secret", Value: name}, {Label: "Cause", Value: secret.Explained(cause).Error()}},
		Details: fmt.Sprintf("%v\n\nWithout it, these fail: %s.\n\nFix the source on the host, such as a login, then try again. Or give the session a value with the command below.", secret.Explained(cause), strings.Join(secretUsers(p, name), ", ")),
		Command: command,
		Scope:   "secret " + name,
	}
	_, id := s.manager.Hold(req, pendingTTL, 0, func(d approval.Decision) {
		if d.Verdict != approval.VerdictAllow {
			s.mu.Lock()
			s.dismissedSecrets[name] = true
			s.mu.Unlock()
			return
		}
		s.deps.Secrets.Retry(name)
		go func() { _, _ = carding{s}.Get(context.Background(), name) }()
	})
	return id
}
