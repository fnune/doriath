package askpass

import (
	"errors"
	"testing"

	"github.com/fnune/doriath/internal/secret"
)

func TestNewPicksTheDialogOfTheDesktop(t *testing.T) {
	env := func(vars map[string]string) func(string) string {
		return func(k string) string { return vars[k] }
	}
	found := func(string) (string, error) { return "/usr/bin/pinentry", nil }
	missing := func(string) (string, error) { return "", errors.New("not found") }
	if a := New(env(map[string]string{"SSH_ASKPASS": "/usr/bin/ksshaskpass"}), found); a != nil {
		t.Errorf("without a display: %#v", a)
	}
	if a := New(env(map[string]string{"WAYLAND_DISPLAY": "wayland-0", "SSH_ASKPASS": "/usr/bin/ksshaskpass"}), found); !isProgram(a, "/usr/bin/ksshaskpass") {
		t.Errorf("with SSH_ASKPASS: %#v", a)
	}
	if a, ok := New(env(map[string]string{"DISPLAY": ":0"}), found).(Pinentry); !ok || a.Path != "/usr/bin/pinentry" {
		t.Errorf("with pinentry: %#v", a)
	}
	if a := New(env(map[string]string{"DISPLAY": ":0"}), missing); a != nil {
		t.Errorf("without a dialog: %#v", a)
	}
}

func isProgram(a secret.Asker, path string) bool {
	p, ok := a.(Program)
	return ok && len(p.Argv) == 1 && p.Argv[0] == path
}
