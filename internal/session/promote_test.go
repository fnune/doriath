package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/profile"
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
