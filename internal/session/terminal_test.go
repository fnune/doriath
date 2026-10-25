package session

import (
	"slices"
	"testing"

	"github.com/fnune/doriath/internal/config"
)

func TestTerminalEnvNamesTheCommandForYourTerminal(t *testing.T) {
	s := &Session{
		deps: Deps{User: config.User{Terminal: config.Terminal{Env: map[string]string{"HERDR_AGENT": "{command}", "B": "fixed"}}}},
		req:  Request{Command: []string{"/nix/store/x-claude/bin/claude", "--resume"}},
	}
	want := []string{"B=fixed", "HERDR_AGENT=claude"}
	if got := s.terminalEnv(); !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
