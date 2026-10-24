package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/profile"
)

func TestAnAllowedReadShowsTheDirectoryReadOnly(t *testing.T) {
	allow := approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession}
	notifier := &answering{seen: make(chan approval.Request, 1), decision: &allow}
	s := newTestSession(t, notifier)
	s.peers.init.Store(1)
	notes := filepath.Join(s.home, "notes")
	mkdirAll(t, notes)
	if _, err := s.requestRead(notes, "the design docs"); err != nil {
		t.Fatal(err)
	}
	req := <-notifier.seen
	if req.Kind != approval.KindRead || req.Note != "the design docs" || !strings.Contains(req.Keep, "[[mounts]]") {
		t.Errorf("request = %+v", req)
	}
	if len(s.promoted.reads) != 1 || s.promoted.reads[0].Path != notes {
		t.Errorf("reads = %+v", s.promoted.reads)
	}
	last := s.req.Profile.Mounts[len(s.req.Profile.Mounts)-1]
	if last.Path != notes || last.Mode != profile.ModeRead {
		t.Errorf("mount = %+v", last)
	}
}

func TestReadRequestsThatDoriathRefusesBeforeAsking(t *testing.T) {
	notifier := &answering{seen: make(chan approval.Request, 1)}
	s := newTestSession(t, notifier)
	ssh := filepath.Join(s.home, ".ssh")
	visible := filepath.Join(s.home, "work")
	file := filepath.Join(s.home, "notes.txt")
	mkdirAll(t, ssh)
	mkdirAll(t, visible)
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s.req.Profile.Mounts = []profile.Mount{{Path: visible, Mode: profile.ModeRead}}
	for path, want := range map[string]string{
		ssh:                             "doriath does not show",
		visible:                         "already readable",
		file:                            "is a file",
		filepath.Join(s.home, "absent"): "does not exist",
		"relative":                      "absolute path",
	} {
		if _, err := s.requestRead(path, ""); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", path, err, want)
		}
	}
	if len(notifier.seen) != 0 {
		t.Error("a request that doriath refuses must not interrupt you")
	}
}
