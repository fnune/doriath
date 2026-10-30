package session

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/vcs"
)

func TestPromotionRefusesPathsThatWouldWeakenTheJail(t *testing.T) {
	s := newTestSession(t, nil)
	home := s.home
	repo := filepath.Join(home, "repo")
	mkdirAll(t, filepath.Join(repo, "assets"), filepath.Join(home, "work"), filepath.Join(home, "dev", "app"))
	if err := os.Symlink(repo, filepath.Join(home, "link")); err != nil {
		t.Fatal(err)
	}
	s.req.Profile.Mounts = []profile.Mount{
		{Path: repo, Mode: profile.ModeRead},
		{Path: filepath.Join(repo, "secret"), Mode: profile.ModeHide},
		{Path: filepath.Join(home, "work"), Mode: profile.ModeWrite},
		{Path: filepath.Join(home, "dev", "app"), Mode: profile.ModeRead},
	}
	s.req.Profile.Caches = []profile.Cache{{Path: filepath.Join(home, ".claude")}}
	for _, c := range []struct {
		name, path, refusal string
	}{
		{"a relative path", "repo/assets", "name an absolute path"},
		{"a path through a symlink", filepath.Join(home, "link", "assets"), "goes through a symlink"},
		{"the root", "/", "whole filesystem"},
		{"the home directory", home, "whole home directory"},
		{"ssh keys", filepath.Join(home, ".ssh", "new"), "holds keys, logins, config that names programs the host runs, or doriath's own state"},
		{"a profile cache", filepath.Join(home, ".claude", "settings"), "holds keys, logins, config that names programs the host runs, or doriath's own state"},
		{"doriath's config", filepath.Join(s.deps.Paths.Config, "profiles"), "holds keys, logins, config that names programs the host runs, or doriath's own state"},
		{"doriath's state", filepath.Join(s.deps.Paths.State, "backups"), "holds keys, logins, config that names programs the host runs, or doriath's own state"},
		{"doriath's cache", s.deps.Paths.Cache, "holds keys, logins, config that names programs the host runs, or doriath's own state"},
		{"a trusted system root", "/usr/share/doriath-test", "trust programs under it by name"},
		{"devices", "/dev/shm/doriath-test", "system paths"},
		{"the runtime directory", "/run/doriath-test", "system paths"},
		{"the shared temporary directory", "/var/tmp/doriath-test", "system paths"},
		{"a git store", filepath.Join(repo, ".git", "hooks"), "inside .git or .jj"},
		{"a jj store", filepath.Join(repo, ".jj", "repo"), "inside .git or .jj"},
		{"a hidden path", filepath.Join(repo, "secret", "key"), "the profile hides " + filepath.Join(repo, "secret")},
		{"a writable path", filepath.Join(home, "work", "sub"), "already writable"},
		{"the parent of a mount", filepath.Join(home, "dev"), "it holds " + filepath.Join(home, "dev", "app")},
		{"a path Landlock cannot open later", "/etc/doriath-test", "Landlock fixes its rules"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := s.checkPromotion(c.path)
			if err == nil || !strings.Contains(err.Error(), c.refusal) {
				t.Fatalf("checkPromotion(%s) = %v, want %q", c.path, err, c.refusal)
			}
		})
	}
}

func TestPromotionAcceptsAReadOnlyPathAndCleansIt(t *testing.T) {
	s := newTestSession(t, nil)
	repo := filepath.Join(s.home, "repo")
	mkdirAll(t, filepath.Join(repo, "assets"))
	s.req.Profile.Mounts = []profile.Mount{{Path: repo, Mode: profile.ModeRead}}
	for _, path := range []string{repo + "/assets/../assets/", repo + "/not/yet/there"} {
		got, err := s.checkPromotion(path)
		if err != nil || got != filepath.Clean(path) {
			t.Errorf("checkPromotion(%s) = %q, %v", path, got, err)
		}
	}
}

func TestDeepestExistingFindsTheClosestAncestor(t *testing.T) {
	dir := t.TempDir()
	if got := deepestExisting(filepath.Join(dir, "a", "b")); got != dir {
		t.Errorf("deepestExisting = %q, want %q", got, dir)
	}
	if got := deepestExisting(dir); got != dir {
		t.Errorf("an existing path is its own deepest: %q", got)
	}
}

func TestTheProfileLinesNamePathsInsideTheRepositoryRelatively(t *testing.T) {
	s := newTestSession(t, nil)
	s.repository = filepath.Join(s.home, "repo")
	for path, want := range map[string]string{
		filepath.Join(s.home, "repo", "assets"): `path = "{repository}/assets"`,
		filepath.Join(s.home, "repo"):           `path = "{repository}"`,
		filepath.Join(s.home, "repository"):     `path = "` + filepath.Join(s.home, "repository") + `"`,
	} {
		if got := s.mountLines(path); !strings.Contains(got, want) || !strings.HasPrefix(got, "[[mounts]]") {
			t.Errorf("lines for %s:\n%s\nwant %s", path, got, want)
		}
	}
}

func TestRequestWriteOfAPathTheAgentCannotSeeAsksYou(t *testing.T) {
	allow := approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession}
	notifier := &answering{seen: make(chan approval.Request, 1), decision: &allow}
	s := newTestSession(t, notifier)
	s.peers.init.Store(1)
	videos := filepath.Join(s.home, "videos")
	mkdirAll(t, videos)
	if _, err := s.requestWrite(videos, "the renders"); err != nil {
		t.Fatal(err)
	}
	req := <-notifier.seen
	if req.Kind != approval.KindPath || !strings.Contains(req.Details, "which the jail does not show") || req.Note != "the renders" {
		t.Errorf("request = %+v", req)
	}
	if len(s.promoted.requests) != 1 || s.promoted.requests[0].Visible {
		t.Errorf("promotions = %+v", s.promoted.requests)
	}
}

func TestRequestWriteOfAMissingPathAsksTheUserToCreateItFirst(t *testing.T) {
	notifier := &answering{seen: make(chan approval.Request, 1)}
	s := newTestSession(t, notifier)
	_, err := s.requestWrite(filepath.Join(s.home, "videos"), "")
	if err == nil || !strings.Contains(err.Error(), "does not exist: ask the user to create it") {
		t.Fatalf("err = %v", err)
	}
	if len(notifier.seen) != 0 {
		t.Error("a request that doriath refuses must not interrupt you")
	}
}

func TestRequestWriteAsksWithTheReasonAndTheProfileLines(t *testing.T) {
	s := newTestSession(t, &answering{})
	s.deps.HostWait = 0
	repo := filepath.Join(s.home, "repo")
	s.repository = repo
	s.req.Profile.Mounts = []profile.Mount{{Path: repo, Mode: profile.ModeRead}}
	assets := filepath.Join(repo, "assets")

	res, err := s.requestWrite(assets, "store generated images")
	if err != nil {
		t.Fatal(err)
	}
	if res.Pending == "" || res.Decision.Verdict != approval.VerdictNone {
		t.Fatalf("an unanswered request must stay pending: %+v", res)
	}
	pending := s.manager.Pending()
	if len(pending) != 1 {
		t.Fatalf("pending = %+v", pending)
	}
	req := pending[0]
	if req.ID != res.Pending || req.Kind != approval.KindPath || req.Scope != "path write "+assets || req.Summary != "Let the agent write "+assets {
		t.Errorf("request = %+v", req)
	}
	if !strings.Contains(req.Details, "lasts until the session ends") || req.Note != "store generated images" || !strings.Contains(req.Keep, `path = "{repository}/assets"`) {
		t.Errorf("details = %q, note = %q, keep = %q", req.Details, req.Note, req.Keep)
	}
	if len(s.promoted.requests) != 0 {
		t.Error("a pending request promoted the path")
	}
}

func TestRequestWriteLeavesTheMountsWhenYouDeny(t *testing.T) {
	s := newTestSession(t, denying())
	repo := filepath.Join(s.home, "repo")
	s.req.Profile.Mounts = []profile.Mount{{Path: repo, Mode: profile.ModeRead}}
	s.peers.setInit(4242)
	res, err := s.requestWrite(filepath.Join(repo, "assets"), "")
	if err != nil || res.Decision.Verdict != approval.VerdictDeny || res.Pending != "" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if len(s.promoted.requests) != 0 || len(s.req.Profile.Mounts) != 1 {
		t.Errorf("a denied request changed the jail: %+v, %+v", s.promoted.requests, s.req.Profile.Mounts)
	}
}

func TestRequestWriteMakesThePathWritableWhenYouAllow(t *testing.T) {
	s := newTestSession(t, allowing())
	repo := filepath.Join(s.home, "repo")
	s.req.Profile.Mounts = []profile.Mount{{Path: repo, Mode: profile.ModeRead}}
	s.peers.setInit(4242)
	assets := filepath.Join(repo, "assets")
	res, err := s.requestWrite(assets, "")
	if err != nil || res.Decision.Verdict != approval.VerdictAllow {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if len(s.promoted.requests) != 1 {
		t.Fatalf("promotions = %+v", s.promoted.requests)
	}
	if r := s.promoted.requests[0]; r.Path != assets || r.Reaper != 4242 || !r.Visible {
		t.Errorf("promotion = %+v", r)
	}
	if info, err := os.Stat(assets); err != nil || !info.IsDir() {
		t.Errorf("a missing directory must be created before it is mounted: %v", err)
	}
	if !slices.Contains(s.req.Profile.Mounts, profile.Mount{Path: assets, Mode: profile.ModeWrite}) {
		t.Errorf("mounts = %+v", s.req.Profile.Mounts)
	}
	if !strings.Contains(s.audit.String(), `"granted"`) || !strings.Contains(s.audit.String(), assets) {
		t.Errorf("the grant is not in the audit log:\n%s", s.audit)
	}
	if _, err := s.checkPromotion(assets); err == nil || !strings.Contains(err.Error(), "already writable") {
		t.Errorf("a second promotion of the path: %v", err)
	}
}

func TestRequestWriteReportsAnAllowThatCouldNotBeApplied(t *testing.T) {
	s := newTestSession(t, allowing())
	repo := filepath.Join(s.home, "repo")
	s.req.Profile.Mounts = []profile.Mount{{Path: repo, Mode: profile.ModeRead}}
	s.peers.setInit(4242)
	s.promoted.err = errors.New("nsenter: permission denied")
	_, err := s.requestWrite(filepath.Join(repo, "assets"), "")
	if err == nil || !strings.Contains(err.Error(), "nsenter: permission denied") {
		t.Fatalf("the agent must learn that the path is still read-only: %v", err)
	}
}

func TestGrantWriteOfAHiddenHostDirectoryMountsIt(t *testing.T) {
	s := newTestSession(t, nil)
	s.peers.setInit(4242)
	videos := filepath.Join(s.home, "videos")
	mkdirAll(t, videos)
	if err := s.grantWrite(context.Background(), videos); err != nil {
		t.Fatal(err)
	}
	if r := s.promoted.requests[0]; r.Path != videos || r.Visible {
		t.Errorf("a directory the jail cannot see must be attached, not made writable in place: %+v", r)
	}
}

func TestGrantWriteFailsBeforeTheJailRuns(t *testing.T) {
	s := newTestSession(t, nil)
	err := s.grantWrite(context.Background(), filepath.Join(s.home, "videos"))
	if err == nil || !strings.Contains(err.Error(), "the jail is not running yet") {
		t.Fatalf("err = %v", err)
	}
	if len(s.promoted.requests) != 0 {
		t.Error("promoted without a jail")
	}
}

func TestGrantWriteKeepsTheMountsWhenPromotionFails(t *testing.T) {
	s := newTestSession(t, nil)
	s.peers.setInit(4242)
	s.promoted.err = errors.New("nsenter: permission denied")
	videos := filepath.Join(s.home, "videos")
	err := s.grantWrite(context.Background(), videos)
	if err == nil || !strings.Contains(err.Error(), "make "+videos+" writable: nsenter: permission denied") {
		t.Fatalf("err = %v", err)
	}
	if len(s.req.Profile.Mounts) != 0 || strings.Contains(s.audit.String(), `"granted"`) {
		t.Errorf("a failed promotion was recorded as a grant: %+v\n%s", s.req.Profile.Mounts, s.audit)
	}
}

func TestAJoinedIdenticalRequestGetsTheDecision(t *testing.T) {
	s := newTestSession(t, &answering{})
	var grants atomic.Int32
	req := approval.Request{Session: s.id, Kind: approval.KindPath, Summary: "Let the agent write /x", Scope: "path write /x"}
	results := make(chan RequestResult, 2)
	hold := func() {
		res, _ := s.holdAndGrant(req, func() error { grants.Add(1); return nil })
		results <- res
	}
	go hold()
	deadline := time.Now().Add(2 * time.Second)
	for len(s.manager.Pending()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	go hold()
	time.Sleep(20 * time.Millisecond)
	if n := len(s.manager.Pending()); n != 1 {
		t.Fatalf("%d requests pending, want the second to join the first", n)
	}
	if err := s.manager.Decide(s.manager.Pending()[0].ID, approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		select {
		case res := <-results:
			if res.Decision.Verdict != approval.VerdictAllow {
				t.Errorf("result = %+v", res)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("a joined request never got the decision")
		}
	}
	if n := grants.Load(); n != 1 {
		t.Errorf("the grant ran %d times", n)
	}
}

func TestARequestThatTouchesAWarnedPathAsksWithTheWarningAndOnlyOnce(t *testing.T) {
	notifier := &answering{seen: make(chan approval.Request, 3)}
	s := newTestSession(t, notifier)
	s.deps.HostWait = 0
	bin := filepath.Join(s.home, ".local", "bin")
	repo := filepath.Join(s.home, "repo")
	envrc := filepath.Join(repo, ".envrc")
	mkdirAll(t, bin, repo)
	if err := os.WriteFile(envrc, []byte("use flake\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.req.Profile.Mounts = []profile.Mount{{Path: repo, Mode: profile.ModeWrite}, {Path: envrc, Mode: profile.ModeRead}}
	s.req.Profile.PathRules = profile.PathRules{
		Warn: []profile.PathWarning{{Path: bin, Reason: "Your shells run programs from it."}},
		Hold: []profile.PathHold{{Path: envrc, Reason: "direnv runs it.", Missing: profile.MissingHold}},
	}
	if _, err := s.requestWrite(filepath.Join(s.home, ".local"), "a helper"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.requestRead(bin, "look"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.requestEdit(envrc, "use flake\necho hi\n", "add a line"); err != nil {
		t.Fatal(err)
	}
	write, read, edit := <-notifier.seen, <-notifier.seen, <-notifier.seen
	if write.Warning != "The request touches "+bin+". Your shells run programs from it." || write.Keep != "" || write.Offers(approval.AnswerSession) {
		t.Errorf("write = %+v", write)
	}
	if read.Warning != "" {
		t.Errorf("a read of a path that the host runs needs no warning: %+v", read)
	}
	if edit.Warning != "The request touches "+envrc+". direnv runs it." {
		t.Errorf("edit = %+v", edit)
	}
}

func TestAPathThatTheProfileRefusesIsRefusedLikeYourKeys(t *testing.T) {
	s := newTestSession(t, nil)
	tokens := filepath.Join(s.home, ".tokens")
	mkdirAll(t, tokens)
	s.req.Profile.PathRules.Refuse = []string{tokens}
	for _, path := range []string{tokens, filepath.Join(tokens, "new")} {
		if _, err := s.checkPromotion(path); err == nil || !strings.Contains(err.Error(), "holds keys, logins, config that names programs the host runs, or doriath's own state") {
			t.Errorf("%s: err = %v", path, err)
		}
	}
}

func TestAWriteGrantOfAVisibleParentKeepsTheMountsInside(t *testing.T) {
	s := newTestSession(t, nil)
	project := filepath.Join(s.home, "project")
	mkdirAll(t, filepath.Join(project, "src", "presets"), filepath.Join(project, "vendor"), filepath.Join(project, "secret"))
	s.req.Profile.Mounts = []profile.Mount{
		{Path: project, Mode: profile.ModeRead},
		{Path: filepath.Join(project, "src", "presets"), Mode: profile.ModeWrite},
		{Path: filepath.Join(project, "vendor"), Mode: profile.ModeRead},
		{Path: filepath.Join(project, "secret"), Mode: profile.ModeHide},
	}
	for _, path := range []string{project, filepath.Join(project, "src")} {
		if _, err := s.checkPromotion(path); err != nil {
			t.Errorf("checkPromotion(%s) = %v", path, err)
		}
	}
}

func TestAWriteGrantOfAnUnseenParentCoversOnlyWritableMounts(t *testing.T) {
	s := newTestSession(t, nil)
	project := filepath.Join(s.home, "project")
	mkdirAll(t, filepath.Join(project, "presets"), filepath.Join(project, "vendor"), filepath.Join(project, "secret"))
	presets := profile.Mount{Path: filepath.Join(project, "presets"), Mode: profile.ModeWrite}
	s.req.Profile.Mounts = []profile.Mount{presets}
	if _, err := s.checkPromotion(project); err != nil {
		t.Fatalf("a host directory attached over a writable mount opens nothing: %v", err)
	}
	for _, nested := range []profile.Mount{{Path: filepath.Join(project, "vendor"), Mode: profile.ModeRead}, {Path: filepath.Join(project, "secret"), Mode: profile.ModeHide}} {
		s.req.Profile.Mounts = []profile.Mount{presets, nested}
		if _, err := s.checkPromotion(project); err == nil || !strings.Contains(err.Error(), "it holds "+nested.Path) {
			t.Errorf("a host directory attached over a %s mount must be refused: %v", nested.Mode, err)
		}
	}
}

func TestAWriteGrantLeavesGuardsInsideAReadOnlyMountToThatMount(t *testing.T) {
	s := newTestSession(t, nil)
	s.peers.setInit(4242)
	roots, err := vcs.NewRootGuard(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(roots.Close)
	s.roots = roots
	project := filepath.Join(s.home, "project")
	vendored := filepath.Join(project, "vendor", "lib")
	mkdirAll(t, filepath.Join(project, ".git"), filepath.Join(vendored, ".git"))
	s.req.Profile.Mounts = []profile.Mount{
		{Path: project, Mode: profile.ModeRead},
		{Path: filepath.Join(project, "vendor"), Mode: profile.ModeRead},
	}
	if err := s.grantWrite(context.Background(), project); err != nil {
		t.Fatal(err)
	}
	guards := s.promoted.requests[0].Guards
	if !slices.ContainsFunc(guards, func(g string) bool { return within(g, filepath.Join(project, ".git")) }) {
		t.Errorf("the project's own repository lost its guards: %v", guards)
	}
	if slices.ContainsFunc(guards, func(g string) bool { return within(g, vendored) }) {
		t.Errorf("a guard inside the read-only vendor mount would pin it writable: %v", guards)
	}
}
