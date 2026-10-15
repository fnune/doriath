//go:build integration

package session_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fnune/girdle/internal/approval"
	"github.com/fnune/girdle/internal/control"
	"github.com/fnune/girdle/internal/session"
)

// TestRequestAndGrantWrite makes paths writable in a running jail: one the
// agent asks for and you allow, and one you grant from the host that the
// jail could not see before.
func TestRequestAndGrantWrite(t *testing.T) {
	e := newEnv(t)
	e.hostWait = 30 * time.Second
	repo := filepath.Join(e.home, "app")
	outside := filepath.Join(e.home, "videos")
	for _, d := range []string{filepath.Join(repo, "assets"), outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	git(t, repo, "init", "-q", "-b", "main")
	marker := filepath.Join(e.work, "granted")
	e.cwd = repo
	p := e.profile(fmt.Sprintf("\n[[mounts]]\npath = %q\nmode = \"read\"\n", repo))
	code, out := e.run(p, fmt.Sprintf(`
set -u
G=/run/girdle-bin/girdle
R=%[1]s
touch $R/assets/x 2>/dev/null && echo "FAIL writable before the request"
$G request write $R/assets --reason "store generated images" || echo "FAIL request"
touch $R/assets/x || echo "FAIL not writable after the allow"
touch $R/other 2>/dev/null && echo "FAIL the rest of the repository became writable"
$G request write $R/.git/config 2>&1 | grep -q '.git or .jj' || echo "FAIL a control file was not refused"
$G request write $HOME/.config/jj 2>&1 | grep -q 'config that names programs' || echo "FAIL jj's config was not refused"
touch %[3]s
for _ in $(seq 100); do [ -d %[2]s ] && touch %[2]s/clip 2>/dev/null && break; sleep 0.1; done
touch %[2]s/clip || echo "FAIL the granted host directory is not writable"
echo done
`, repo, outside, marker), func() {
		req := e.decideNext(approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession, By: "test"})
		if req.Kind != approval.KindPath || !strings.Contains(req.Details, "store generated images") || !strings.Contains(req.Details, `path = "{repository}/assets"`) {
			t.Errorf("request: %+v", req)
		}
		for i := 0; i < 200; i++ {
			if _, err := os.Stat(marker); err == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		socks, _ := filepath.Glob(filepath.Join(e.paths.Sessions(), "*", session.ControlSocket))
		var res session.GrantWriteResult
		if len(socks) != 1 {
			t.Errorf("control sockets: %v", socks)
			return
		}
		if err := control.Call(context.Background(), socks[0], session.MethodGrantWrite, session.GrantWriteParams{Path: outside}, &res); err != nil {
			t.Errorf("grant: %v", err)
		}
	})
	if code != 0 || !strings.Contains(out, "done") || strings.Contains(out, "FAIL") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	for _, f := range []string{filepath.Join(repo, "assets", "x"), filepath.Join(outside, "clip")} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("the write did not reach the host: %v", err)
		}
	}
}

// TestGrantKeepsRepositoryGuards makes directories that hold repositories
// writable, one the jail sees and one it does not: their files become
// writable, and git's control files stay read-only, as in a write mount.
func TestGrantKeepsRepositoryGuards(t *testing.T) {
	e := newEnv(t)
	e.hostWait = 30 * time.Second
	seen := filepath.Join(e.home, "projects")
	unseen := filepath.Join(e.home, "elsewhere")
	for _, repo := range []string{filepath.Join(seen, "app"), filepath.Join(unseen, "lib")} {
		if err := os.MkdirAll(repo, 0o700); err != nil {
			t.Fatal(err)
		}
		git(t, repo, "init", "-q", "-b", "main")
		if err := os.RemoveAll(filepath.Join(repo, ".git", "hooks")); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(e.work, "asked")
	p := e.profile(fmt.Sprintf("\n[[mounts]]\npath = %q\nmode = \"read\"\n", seen))
	code, out := e.run(p, fmt.Sprintf(`
set -u
G=/run/girdle-bin/girdle
probe() {
  touch $1/file || echo "FAIL $1 is not writable"
  echo x >> $1/.git/config 2>/dev/null && echo "FAIL $1/.git/config is writable"
  mkdir -p $1/.git/hooks 2>/dev/null; touch $1/.git/hooks/pre-commit 2>/dev/null && echo "FAIL $1 took a hook"
  echo /tmp > $1/.git/commondir 2>/dev/null && echo "FAIL $1/.git/commondir is writable"
  touch $1/.git/refs/heads/x || echo "FAIL $1/.git/refs is not writable"
}
$G request write %[1]s --reason "work on several projects" || echo "FAIL request"
probe %[1]s/app
touch %[3]s
for _ in $(seq 100); do [ -d %[2]s/lib ] && break; sleep 0.1; done
probe %[2]s/lib
echo done
`, seen, unseen, marker), func() {
		e.decideNext(approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession, By: "test"})
		for i := 0; i < 200; i++ {
			if _, err := os.Stat(marker); err == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		socks, _ := filepath.Glob(filepath.Join(e.paths.Sessions(), "*", session.ControlSocket))
		if len(socks) != 1 {
			t.Errorf("control sockets: %v", socks)
			return
		}
		if err := control.Call(context.Background(), socks[0], session.MethodGrantWrite, session.GrantWriteParams{Path: unseen}, &session.GrantWriteResult{}); err != nil {
			t.Errorf("grant: %v", err)
		}
	})
	if code != 0 || !strings.Contains(out, "done") || strings.Contains(out, "FAIL") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}
