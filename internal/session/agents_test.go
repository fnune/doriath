package session

import (
	"strings"
	"testing"

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
