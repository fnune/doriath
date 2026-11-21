//go:build integration

package session_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/keyringtest"
)

const remoteServer = "\n[[mcp]]\nname = \"remote\"\nurl = \"https://example.com/mcp\"\n"

func agentBinary(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not installed", name)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

func agentEnv(t *testing.T, name string) *env {
	e := newEnv(t)
	e.agent, e.modules = name, []string{name}
	return e
}

func TestCodexReadsTheSessionsConfigAndTheProfilesServers(t *testing.T) {
	codex := agentBinary(t, "codex")
	e := agentEnv(t, "codex")
	code, out := e.run(e.profile(remoteServer), `
[ "$1" = --dangerously-bypass-hook-trust ] || echo "FAIL codex starts without the hook trust flag: $*"
`+codex+` mcp list 2>&1 | grep -q 'https://example.com/mcp' || echo "FAIL codex lacks the profile's server"
`+codex+` "$@" debug prompt-input 2>/dev/null | grep -q 'doriath request wait HOST' || echo "FAIL codex lacks the session text"
grep -q '__hook codex permission-request' ~/.codex/hooks.json || echo "FAIL no permission hook"
(echo '[hooks]' >> ~/.codex/config.toml) 2>/dev/null && echo "FAIL the agent can change its config"
true
`, nil)
	if code != 0 || strings.Contains(out, "FAIL") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}

func TestGeminiReadsTheProfilesServersAndTheSessionText(t *testing.T) {
	gemini := agentBinary(t, "gemini")
	e := agentEnv(t, "gemini")
	code, out := e.run(e.profile(remoteServer), `
`+gemini+` mcp list 2>&1 | grep -q 'example.com/mcp' || { echo "FAIL gemini lacks the profile's server"; `+gemini+` mcp list 2>&1 | head -20; }
grep -q 'doriath request wait HOST' ~/.gemini/GEMINI.md || echo "FAIL no session text in GEMINI.md"
true
`, nil)
	if code != 0 || strings.Contains(out, "FAIL") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}

func TestOpencodeReadsTheProfilesServersAndTheSessionText(t *testing.T) {
	opencode := agentBinary(t, "opencode")
	e := agentEnv(t, "opencode")
	code, out := e.run(e.profile(remoteServer), `
config=$(`+opencode+` debug config 2>&1)
echo "$config" | grep -q 'https://example.com/mcp' || { echo "FAIL opencode lacks the profile's server"; echo "$config" | head -40; }
echo "$config" | grep -q '/run/doriath/opencode-instructions.md' || echo "FAIL opencode lacks the session text"
true
`, nil)
	if code != 0 || strings.Contains(out, "FAIL") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}

func TestClaudeStartsInAWritableCheckoutWithoutProjectSettings(t *testing.T) {
	e := agentEnv(t, "claude")
	e.modules = append(e.modules, "vcs-readwrite")
	git(t, e.work, "init", "-q", "-b", "main")
	code, out := e.run(e.profile(""), `echo started`, nil)
	if code != 0 || !strings.Contains(out, "started") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}

func TestClaudeNeedsTheLoginBeforeTheAgentStarts(t *testing.T) {
	e := agentEnv(t, "claude")
	e.logins = keyringtest.New()
	_, out, err := e.start(e.profile(""), `echo ran > "$PWD/ran"`, nil)
	if err == nil || !strings.Contains(err.Error(), "not signed in: run `doriath profiles login it claude`") {
		t.Fatalf("err = %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(e.work, "ran")); err == nil {
		t.Error("the agent started without the login")
	}
}
