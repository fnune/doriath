package session

import (
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/jail"
	"github.com/fnune/doriath/internal/modules"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/vcs"
)

func moduleSession(t *testing.T, notifier approval.Notifier, body string) (*testSession, string) {
	t.Helper()
	s := newTestSession(t, notifier)
	l := &profile.Loader{Profiles: fstest.MapFS{"p.toml": {Data: []byte(`modules = ["vcs-readwrite", "claude"]` + "\n" + body)}}, Modules: []fs.FS{modules.FS}, Home: s.home, Builtins: modules.Builtins}
	p, err := l.Load("p")
	if err != nil {
		t.Fatal(err)
	}
	s.unresolved = p
	s.modulesByRepository = map[string][]string{}
	s.repository = filepath.Join(s.home, "repo")
	other := filepath.Join(s.home, "other")
	mkdirAll(t, filepath.Join(s.repository, ".git"), filepath.Join(other, ".git"))
	s.peers.init.Store(1)
	roots, err := vcs.NewRootGuard(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(roots.Close)
	s.roots = roots
	return s, other
}

func gitRepository(t *testing.T, dir string) {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	if err := os.RemoveAll(filepath.Join(dir, ".git")); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(git, "init", "-q", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
}

func TestRequestModuleRefusesWhatTheProfileDoesNotGrant(t *testing.T) {
	s, other := moduleSession(t, nil, `
[[mounts]]
path = "{repository}/secrets"
mode = "hide"
`)
	plain := filepath.Join(s.home, "plain")
	mkdirAll(t, plain, filepath.Join(other, "secrets"))
	if err := os.WriteFile(filepath.Join(other, "secrets", "token"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, module, path, refusal string
	}{
		{"a relative path", "vcs-readwrite", "other", "name an absolute path"},
		{"a folder outside a repository", "vcs-readwrite", plain, "is not in a git or jj repository"},
		{"the session's repository", "vcs-readwrite", s.repository, "the repository of this session"},
		{"a module the profile does not use", "github", other, `does not use module "github"`},
		{"a hidden path with content", "vcs-readwrite", filepath.Join(other, "src"), "cannot hide a path while the jail runs"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := s.requestModule(c.module, c.path, ""); err == nil || !strings.Contains(err.Error(), c.refusal) {
				t.Fatalf("requestModule(%s, %s) = %v, want %q", c.module, c.path, err, c.refusal)
			}
		})
	}
}

func TestRequestModuleRefusesARepositoryThatHoldsAMountOfTheJail(t *testing.T) {
	s, other := moduleSession(t, nil, "")
	s.req.Profile.Mounts = []profile.Mount{{Path: filepath.Join(other, "docs"), Mode: profile.ModeRead}}
	if _, err := s.requestModule("vcs-readwrite", other, ""); err == nil || !strings.Contains(err.Error(), "start a session in "+other) {
		t.Fatalf("err = %v", err)
	}
}

func TestVCSReadwriteInAShownRepositoryKeepsItsGuardsAndRecordsItsBranches(t *testing.T) {
	allow := approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingOnce}
	notifier := &answering{seen: make(chan approval.Request, 1), decision: &allow}
	s, other := moduleSession(t, notifier, "")
	gitRepository(t, other)
	git, _ := exec.LookPath("git")
	s.deps.Git = git
	if err := os.WriteFile(filepath.Join(other, ".envrc"), []byte("use flake\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.req.Profile.Mounts = []profile.Mount{{Path: other, Mode: profile.ModeRead}, {Path: filepath.Join(other, "src"), Mode: profile.ModeWrite}}
	mkdirAll(t, filepath.Join(other, "src"))

	if _, err := s.requestModule("vcs-readwrite", filepath.Join(other, "src"), "commit the fix"); err != nil {
		t.Fatal(err)
	}
	req := <-notifier.seen
	if req.Summary != "Let the agent use module vcs-readwrite in "+other || !strings.Contains(req.Details, "can commit") || req.Note != "commit the fix" {
		t.Errorf("request = %+v", req)
	}
	if len(s.promoted.requests) != 1 {
		t.Fatalf("promotions = %+v", s.promoted.requests)
	}
	w := s.promoted.requests[0]
	if w.Path != other || !w.Visible {
		t.Errorf("promotion = %+v", w)
	}
	for _, guard := range []string{".envrc", ".git/config", ".git/hooks", ".claude/settings.json", ".mcp.json"} {
		if !slices.Contains(w.Guards, filepath.Join(other, guard)) {
			t.Errorf("guards lack %s: %v", guard, w.Guards)
		}
	}
	if !slices.Contains(s.status().Writable, other) {
		t.Errorf("status = %+v", s.status().Writable)
	}
	rec, err := vcs.Load(recordPath(s.deps.Paths, s.id))
	if err != nil || len(rec.Repos) != 1 || rec.Repos[0].Path != other {
		t.Errorf("record = %+v, %v", rec, err)
	}
	if !strings.Contains(s.audit.String(), `"module":"vcs-readwrite"`) {
		t.Errorf("audit:\n%s", s.audit)
	}
	if _, err := s.requestModule("vcs-readwrite", other, ""); err == nil || !strings.Contains(err.Error(), "applies in "+other+" already") {
		t.Errorf("a second request: %v", err)
	}
	if w, ok := s.req.Profile.PathRules.Warning(filepath.Join(other, ".envrc"), false); !ok || w.Path != filepath.Join(other, ".envrc") {
		t.Errorf("a later write request of .envrc does not warn: %+v, %v", w, ok)
	}
	s.finishRepositories(io.Discard)
}

func TestClaudeInAnUnseenRepositoryShowsItAndWritesItsWorktrees(t *testing.T) {
	s, other := moduleSession(t, nil, "")
	s.deps.HostWait = 0
	if err := s.grantModule(t.Context(), "claude", other); err != nil {
		t.Fatal(err)
	}
	if len(s.promoted.reads) != 1 || s.promoted.reads[0].Path != other {
		t.Errorf("reads = %+v", s.promoted.reads)
	}
	worktrees := filepath.Join(other, ".claude", "worktrees")
	if len(s.promoted.requests) != 1 || s.promoted.requests[0].Path != worktrees || !s.promoted.requests[0].Visible {
		t.Errorf("promotions = %+v", s.promoted.requests)
	}
	if info, err := os.Stat(worktrees); err != nil || !info.IsDir() {
		t.Errorf("worktrees: %v", err)
	}
	if _, err := os.Stat(recordPath(s.deps.Paths, s.id)); err == nil {
		t.Error("claude opens no store, so the session records none")
	}
}

func TestAWaitForARepositoryFindsItsModuleRequest(t *testing.T) {
	s, other := moduleSession(t, &answering{}, "")
	s.deps.HostWait = 0
	res, err := s.requestModule("vcs-readwrite", other, "")
	if err != nil || res.Pending == "" {
		t.Fatalf("res = %+v, %v", res, err)
	}
	if got := s.pathScope(other); got != moduleScope("vcs-readwrite", other) {
		t.Errorf("scope = %q", got)
	}
}

func TestStatusNamesTheModulesForAnotherRepository(t *testing.T) {
	s, _ := moduleSession(t, nil, "")
	st := s.status()
	if !slices.Equal(st.Modules, []string{"vcs-readwrite", "claude"}) {
		t.Errorf("modules = %v", st.Modules)
	}
	if text := st.Describe(); !strings.Contains(text, "doriath request module MODULE PATH") || !strings.Contains(text, "  - claude\n") {
		t.Errorf("describe:\n%s", text)
	}
}

func TestAGrantHidesAnEmptyPlaceholderWithAReadOnlyGuardAndRefusesContent(t *testing.T) {
	dir := realTempDir(t)
	held := filepath.Join(dir, "repo", ".doriath")
	mkdirAll(t, held)
	plan := jail.Extension{Write: []jail.Promotion{{Path: dir}, {Path: filepath.Join(dir, "repo")}}, Hide: []string{held}}
	if err := guardEmptyHides(&plan); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(plan.Write[1].Guards, held) || len(plan.Write[0].Guards) != 0 {
		t.Errorf("the deepest writable path must guard the placeholder: %+v", plan.Write)
	}
	if err := os.WriteFile(filepath.Join(held, "p.toml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := guardEmptyHides(&plan); err == nil {
		t.Error("a guard would show the content that the profile hides")
	}
}
