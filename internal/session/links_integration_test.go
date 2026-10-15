//go:build integration

package session_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPlantedLinkIsRefusedInTheNextSession puts a symlink to a directory
// outside the profile on the way to a mount inside the writable checkout,
// as an agent could in a session that did not have the mount. The next
// session must not bind the target in its place.
func TestPlantedLinkIsRefusedInTheNextSession(t *testing.T) {
	e := newEnv(t)
	outside := filepath.Join(e.home, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(e.work, ".claude", "worktrees")
	p := e.profile("\n[[mounts]]\npath = \"{current}/.claude/worktrees\"\nmode = \"write\"\n")
	if err := os.Symlink(outside, filepath.Dir(inner)); err != nil {
		t.Fatal(err)
	}
	_, out, err := e.start(p, "touch "+filepath.Join(inner, "owned"), nil)
	if err == nil || !strings.Contains(err.Error(), "goes through the symlink") {
		t.Fatalf("the session must refuse the planted link: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(outside, "worktrees")); !os.IsNotExist(err) {
		t.Errorf("girdle created a directory through the link: %v", err)
	}
}
