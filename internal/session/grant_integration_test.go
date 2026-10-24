//go:build integration

package session_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/session"
)

// TestRequestAndGrantWrite makes paths writable in a running jail: one the
// agent asks for and you allow, and one you grant from the host that the
// jail could not see before.
func TestRequestWriteOfASeenAndAnUnseenPath(t *testing.T) {
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
	e.cwd = repo
	p := e.profile(fmt.Sprintf("\n[[mounts]]\npath = %q\nmode = \"read\"\n", repo))
	code, out := e.run(p, fmt.Sprintf(`
set -u
G=/run/doriath-bin/doriath
R=%[1]s
touch $R/assets/x 2>/dev/null && echo "FAIL writable before the request"
$G request write $R/assets --reason "store generated images" || echo "FAIL request"
touch $R/assets/x || echo "FAIL not writable after the allow"
touch $R/other 2>/dev/null && echo "FAIL the rest of the repository became writable"
$G request write $R/.git/config 2>&1 | grep -q '.git or .jj' || echo "FAIL a control file was not refused"
$G request write $HOME/.config/jj 2>&1 | grep -q 'config that names programs' || echo "FAIL jj's config was not refused"
$G request write %[2]s --reason "save the clips" || echo "FAIL request of the unseen folder"
touch %[2]s/clip || echo "FAIL the unseen folder is not writable after the allow"
echo done
`, repo, outside), func() {
		allow := approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession, By: "test"}
		req := e.decideNext(allow)
		if req.Kind != approval.KindPath || req.Note != "store generated images" || !strings.Contains(req.Keep, `path = "{repository}/assets"`) {
			t.Errorf("request: %+v", req)
		}
		if req := e.decideNext(allow); !strings.Contains(req.Details, "does not show") {
			t.Errorf("request of the unseen folder: %+v", req)
		}
		socks, _ := filepath.Glob(filepath.Join(e.paths.Sessions(), "*", session.ControlSocket))
		if len(socks) != 1 {
			t.Errorf("control sockets: %v", socks)
			return
		}
		var entry session.Entry
		var err error
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			var data []byte
			entry = session.Entry{}
			if data, err = os.ReadFile(filepath.Join(filepath.Dir(socks[0]), session.EntryFile)); err == nil && json.Unmarshal(data, &entry) == nil && slices.Contains(entry.AgentWritable, outside) {
				break
			}
		}
		if !slices.Contains(entry.AgentWritable, outside) {
			t.Errorf("the session entry must list the grant for doriath exec: %+v, %v", entry, err)
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

// TestAWriteRequestKeepsRepositoryGuards makes directories that hold
// repositories writable, one the jail sees and one it does not: their files
// become writable, and git's control files stay read-only, as in a write
// mount.
func TestAWriteRequestKeepsRepositoryGuards(t *testing.T) {
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
	p := e.profile(fmt.Sprintf("\n[[mounts]]\npath = %q\nmode = \"read\"\n", seen))
	code, out := e.run(p, fmt.Sprintf(`
set -u
G=/run/doriath-bin/doriath
probe() {
  touch $1/file || echo "FAIL $1 is not writable"
  echo x >> $1/.git/config 2>/dev/null && echo "FAIL $1/.git/config is writable"
  mkdir -p $1/.git/hooks 2>/dev/null; touch $1/.git/hooks/pre-commit 2>/dev/null && echo "FAIL $1 took a hook"
  echo /tmp > $1/.git/commondir 2>/dev/null && sleep 1 && [ -e $1/.git/commondir ] && echo "FAIL $1/.git/commondir stayed"
  touch $1/.git/refs/heads/x || echo "FAIL $1/.git/refs is not writable"
}
$G request write %[1]s --reason "work on several projects" || echo "FAIL request"
probe %[1]s/app
$G request write %[2]s --reason "work on the library" || echo "FAIL request of the unseen folder"
probe %[2]s/lib
echo done
`, seen, unseen), func() {
		allow := approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession, By: "test"}
		e.decideNext(allow)
		e.decideNext(allow)
	})
	if code != 0 || !strings.Contains(out, "done") || strings.Contains(out, "FAIL") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}

func TestTheAgentAsksToReadAndWriteFoldersTheJailDoesNotShow(t *testing.T) {
	e := newEnv(t)
	e.hostWait = 30 * time.Second
	docs := filepath.Join(e.home, "docs")
	renders := filepath.Join(e.home, "renders")
	for _, d := range []string{docs, renders} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(docs, "design.md"), []byte("the plan\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := e.run(e.profile(""), fmt.Sprintf(`
set -u
G=/run/doriath-bin/doriath
cat %[1]s/design.md 2>/dev/null && echo "FAIL readable before the request"
$G request read %[1]s --reason "the design docs" || echo "FAIL read request"
grep -q 'the plan' %[1]s/design.md || echo "FAIL not readable after the allow"
touch %[1]s/new 2>/dev/null && echo "FAIL a read grant is writable"
$G request write %[2]s --reason "store renders" || echo "FAIL write request"
touch %[2]s/frame || echo "FAIL not writable after the allow"
$G request read $HOME/.ssh 2>&1 | grep -q 'does not exist\|does not show' || echo "FAIL ssh was not refused"
$G request read %[1]s-missing 2>&1 | grep -q 'ask the user to create it' || echo "FAIL a missing folder was not refused"
echo done
`, docs, renders), func() {
		allow := approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession, By: "test"}
		if req := e.decideNext(allow); req.Kind != approval.KindRead || req.Note != "the design docs" {
			t.Errorf("read request: %+v", req)
		}
		if req := e.decideNext(allow); req.Kind != approval.KindPath || !strings.Contains(req.Details, "does not show") {
			t.Errorf("write request: %+v", req)
		}
	})
	if code != 0 || !strings.Contains(out, "done") || strings.Contains(out, "FAIL") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(renders, "frame")); err != nil {
		t.Errorf("the write did not reach the host: %v", err)
	}
	if _, err := os.Stat(filepath.Join(docs, "new")); err == nil {
		t.Error("the read grant let a write through")
	}
}
