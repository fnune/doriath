//go:build integration

package session_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheAgentReadsYourInstructionsAndWhatTheJailAllows(t *testing.T) {
	e := newEnv(t)
	mine := filepath.Join(e.home, ".agent", "AGENTS.md")
	if err := os.MkdirAll(filepath.Dir(mine), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mine, []byte("Write tests first.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := e.profile("\n[[caches]]\npath = \"~/.agent\"\n\n[agent]\ninstructions = [\"~/.agent/AGENTS.md\", \"~/.other/AGENTS.md\"]\n")
	code, out := e.run(p, `
head -1 ~/.agent/AGENTS.md
grep -q 'example.com' ~/.agent/AGENTS.md || echo "FAIL no hosts in your instructions"
grep -q 'doriath request wait HOST' ~/.other/AGENTS.md || echo "FAIL no session text without a file of yours"
(echo changed > ~/.agent/AGENTS.md) 2>/dev/null && echo "FAIL the agent rewrote its instructions" || true
`, nil)
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "\nWrite tests first.\n") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if data, _ := os.ReadFile(mine); string(data) != "Write tests first.\n" {
		t.Errorf("your file changed: %q", data)
	}
}

func TestGitOverSSHSaysThatTheJailHasNoRouteForIt(t *testing.T) {
	e := newEnv(t)
	_, out := e.run(e.profile(""), `git ls-remote git@forge.example:owner/repo.git 2>&1 | head -3`, nil)
	if !strings.Contains(out, "git tried to reach forge.example over SSH, which has no route out of the jail") {
		t.Fatalf("git said:\n%s", out)
	}
}
