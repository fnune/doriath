package session

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/jail"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/promote"
)

type RequestReadParams struct {
	Path string `json:"path"`
	// Reason is the agent's own text, shown to you as such.
	Reason string `json:"reason,omitempty"`
}

func (s *Session) requestRead(path, reason string) (RequestResult, error) {
	path, err := s.checkRead(path)
	if err != nil {
		return RequestResult{}, err
	}
	req := approval.Request{
		Session: s.id,
		Profile: s.req.Profile.Name,
		Kind:    approval.KindRead,
		Summary: "Let the agent read " + path,
		Details: "The agent asks to read " + path + ", which the jail does not show. An allow shows it, read-only, until the session ends.",
		Note:    reason,
		Keep:    fmt.Sprintf("[[mounts]]\npath = %q", s.profilePath(path)),
		Scope:   "path read " + path,
	}
	s.warn(&req, path, true)
	return s.holdAndGrant(req, func() error { return s.grantRead(context.Background(), path) })
}

func (s *Session) grantRead(ctx context.Context, path string) error {
	path, err := s.checkRead(path)
	if err != nil {
		return err
	}
	reaper := int(s.peers.init.Load())
	if reaper == 0 {
		return errors.New("the jail is not running yet")
	}
	err = s.deps.Read(ctx, promote.Request{
		Reaper:  reaper,
		JailExe: jail.ExePath,
		HostExe: s.deps.Exe,
		Nsenter: s.deps.Nsenter,
		Unshare: s.deps.Unshare,
		Path:    path,
	})
	if err != nil {
		return fmt.Errorf("show %s: %w", path, err)
	}
	s.mu.Lock()
	s.req.Profile.Mounts = append(s.req.Profile.Mounts, profile.Mount{Path: path, Mode: profile.ModeRead})
	s.mu.Unlock()
	s.log.Write("granted", map[string]any{"path": path, "mode": "read"})
	return nil
}

func requireDirectory(path string) error {
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("%s does not exist: ask the user to create it, then ask again", path)
	case err != nil:
		return err
	case !info.IsDir():
		return fmt.Errorf("%s is a file: ask for the directory that holds it", path)
	}
	return nil
}
