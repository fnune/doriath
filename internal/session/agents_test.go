package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/agents"
	"github.com/fnune/doriath/internal/profile"
)

func TestAdapterNeedsTheAgentsModule(t *testing.T) {
	with := &profile.Profile{Name: "work", Modules: []string{"base", "claude"}}
	if a, warning := adapterFor(with, []string{"/usr/bin/claude", "-p", "hi"}); a == nil || warning != "" {
		t.Fatalf("with the claude module: %v, %q", a, warning)
	}
	without := &profile.Profile{Name: "work", Modules: []string{"base"}}
	a, warning := adapterFor(without, []string{"claude"})
	if a != nil || !strings.Contains(warning, "Add the module") {
		t.Fatalf("without the claude module: %v, %q", a, warning)
	}
	if a, warning := adapterFor(with, []string{"make", "build"}); a != nil || warning != "" {
		t.Fatalf("another command: %v, %q", a, warning)
	}
}

func TestAgentCommandComesFromTheProfilesModules(t *testing.T) {
	if got, err := AgentCommand(&profile.Profile{Name: "work", Modules: []string{"base", "claude"}}); err != nil || got != "claude" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := AgentCommand(&profile.Profile{Name: "work", Modules: []string{"base"}}); err == nil || !strings.Contains(err.Error(), "--command") {
		t.Fatalf("no agent module: %v", err)
	}
}

type startingAdapter struct {
	agents.Adapter
	sessions []agents.Session
}

func (a *startingAdapter) Started(s agents.Session) error {
	a.sessions = append(a.sessions, s)
	return nil
}

func TestTouchSetsAPlacedFileToNowSoThatTheAgentSeesAChange(t *testing.T) {
	s := newTestSession(t, &answering{})
	s.jailDir = t.TempDir()
	settings := filepath.Join(s.home, ".claude", "settings.json")
	if err := s.place(settings, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := s.touch(settings); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(s.placed[0].Source)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(stillClock{}.Now()) {
		t.Errorf("mtime = %v, want the clock's now", info.ModTime())
	}
	if err := s.touch(filepath.Join(s.home, "elsewhere")); err == nil {
		t.Error("a path nothing was placed at must be an error")
	}
}

func TestAnAgentThatStartedGetsItsAdaptersHostWork(t *testing.T) {
	s := newTestSession(t, &answering{})
	if err := s.agentStarted(); err != nil {
		t.Fatalf("no adapter: %v", err)
	}
	a := &startingAdapter{}
	s.agent = a
	if err := s.agentStarted(); err != nil {
		t.Fatal(err)
	}
	if len(a.sessions) != 1 || a.sessions[0].Touch == nil {
		t.Errorf("sessions = %+v", a.sessions)
	}
}
