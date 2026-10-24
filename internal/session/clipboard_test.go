package session

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/jail"
)

type stillClipboard struct{}

func (stillClipboard) Types(context.Context) ([]string, error) { return []string{"image/png"}, nil }

func (stillClipboard) Copy(_ context.Context, _ string, w io.Writer) error {
	_, err := w.Write([]byte("png"))
	return err
}

func TestAClipboardReadAsksEachTimeUnlessAllowedForTheSession(t *testing.T) {
	for _, c := range []struct {
		lasting approval.Lasting
		asks    int
	}{
		{approval.LastingOnce, 2},
		{approval.LastingSession, 1},
	} {
		t.Run(string(c.lasting), func(t *testing.T) {
			notifier := &answering{
				decision: &approval.Decision{Verdict: approval.VerdictAllow, Lasting: c.lasting, By: "test"},
				seen:     make(chan approval.Request, 2),
			}
			s := newTestSession(t, notifier)
			for range 2 {
				if err := s.askClipboard(context.Background(), "image/png"); err != nil {
					t.Fatal(err)
				}
			}
			if len(notifier.seen) != c.asks {
				t.Fatalf("asked %d times, want %d", len(notifier.seen), c.asks)
			}
			req := <-notifier.seen
			if req.Kind != approval.KindClipboard || req.Scope != "clipboard image" || !strings.Contains(req.Details, "as image/png") {
				t.Errorf("request = %+v", req)
			}
			if !strings.Contains(s.audit.String(), `"clipboard-read"`) {
				t.Errorf("the read is not in the audit log:\n%s", s.audit)
			}
		})
	}
}

func TestARefusedClipboardReadFails(t *testing.T) {
	s := newTestSession(t, denying())
	if err := s.askClipboard(context.Background(), "image/png"); err == nil {
		t.Fatal("a refused read went through")
	}
	if strings.Contains(s.audit.String(), `"clipboard-read"`) {
		t.Errorf("a refused read is logged as read:\n%s", s.audit)
	}
}

func TestStartClipboardPointsTheJailAtItsDisplay(t *testing.T) {
	s := newTestSession(t, allowing())
	s.jailDir = t.TempDir()
	s.req.Profile.ClipboardImages = true
	s.deps.Clipboard = stillClipboard{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := s.startClipboard(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, c := range s.closers {
			c()
		}
	})
	if s.clipboardEnv["WAYLAND_DISPLAY"] != jail.InJail(WaylandSocket) || s.clipboardEnv["XDG_SESSION_TYPE"] != "wayland" {
		t.Errorf("env = %v", s.clipboardEnv)
	}
	if info, err := os.Stat(filepath.Join(s.jailDir, WaylandSocket)); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Errorf("no display socket: %v", err)
	}
}

func TestStartClipboardWithoutAWaylandSessionWarns(t *testing.T) {
	s := newTestSession(t, allowing())
	s.jailDir = t.TempDir()
	s.req.Profile.ClipboardImages = true
	if err := s.startClipboard(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.clipboardEnv != nil || len(s.notes) != 1 || !strings.Contains(s.notes[0].text, "no Wayland session") {
		t.Errorf("env = %v, notes = %+v", s.clipboardEnv, s.notes)
	}
}

func TestStartClipboardDoesNothingUnlessTheProfileAsks(t *testing.T) {
	s := newTestSession(t, allowing())
	s.deps.Clipboard = stillClipboard{}
	if err := s.startClipboard(context.Background()); err != nil || s.clipboardEnv != nil {
		t.Errorf("env = %v, %v", s.clipboardEnv, err)
	}
}
