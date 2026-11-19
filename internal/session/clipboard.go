package session

import (
	"context"
	"errors"
	"fmt"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/clipboard"
	"github.com/fnune/doriath/internal/clipboard/wayland"
	"github.com/fnune/doriath/internal/jail"
	"github.com/fnune/doriath/internal/term"
)

const WaylandSocket = "wayland.sock"

func (s *Session) startClipboard(ctx context.Context) error {
	if !s.req.Profile.ClipboardImages {
		return nil
	}
	if s.deps.Clipboard == nil {
		s.notes = append(s.notes, note{term.Warn, "the agent cannot read your clipboard: doriath found no Wayland session and wl-paste to read it from"})
		return nil
	}
	l, err := s.listen(WaylandSocket)
	if err != nil {
		return err
	}
	src := clipboard.Images(s.deps.Clipboard, s.askClipboard)
	go func() {
		_ = wayland.Serve(ctx, l, src, func(err error) { s.log.Write("clipboard-error", map[string]string{"error": err.Error()}) })
	}()
	s.clipboardEnv = map[string]string{
		"WAYLAND_DISPLAY":  jail.InJail(WaylandSocket),
		"XDG_SESSION_TYPE": "wayland",
	}
	return nil
}

func (s *Session) askClipboard(ctx context.Context, mimeType string) error {
	d, err := s.manager.Submit(ctx, approval.Request{
		Session: s.id,
		Profile: s.req.Profile.Name,
		Kind:    approval.KindClipboard,
		Summary: "Let the agent read the image in your clipboard",
		Action:  "Read the image you copied",
		Facts:   []approval.Fact{{Label: "Type", Value: mimeType}},
		Details: fmt.Sprintf("The agent asks for the image you copied, as %s. Allow it when you pasted an image; text in your clipboard never reaches the jail.", mimeType),
		Scope:   "clipboard image",
	}, s.deps.HostWait)
	if err != nil {
		return err
	}
	if d.Verdict != approval.VerdictAllow {
		return errors.New("you did not allow reading the clipboard")
	}
	s.log.Write("clipboard-read", map[string]string{"type": mimeType, "by": d.By})
	return nil
}
