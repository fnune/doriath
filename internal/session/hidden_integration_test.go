//go:build integration

package session_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMissingHiddenPathIsHeldForTheSession hides a path that does not
// exist inside a writable mount: the agent cannot create it, and nothing of
// girdle's stays behind.
func TestMissingHiddenPathIsHeldForTheSession(t *testing.T) {
	e := newEnv(t)
	hidden := filepath.Join(e.work, "config", ".envrc")
	p := e.profile(fmt.Sprintf("\n[[mounts]]\npath = %q\nmode = \"hide\"\n", hidden))
	code, out := e.run(p, fmt.Sprintf(`echo x > %[1]q 2>/dev/null && echo "FAIL created"; echo done`, hidden), nil)
	if code != 0 || !strings.Contains(out, "done") || strings.Contains(out, "FAIL") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	for _, p := range []string{hidden, filepath.Dir(hidden)} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s stays after the session: %v", p, err)
		}
	}
}
