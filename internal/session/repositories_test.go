package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/vcs"
)

// repositories lays out, without git, a main repository and a linked
// worktree of it elsewhere, as git writes them.
type repositories struct {
	main, store, linked string
}

func newRepositories(t *testing.T, home string) repositories {
	t.Helper()
	r := repositories{
		main:   filepath.Join(home, "repo"),
		linked: filepath.Join(home, "trees", "feat"),
	}
	r.store = filepath.Join(r.main, ".git")
	admin := filepath.Join(r.store, "worktrees", "feat")
	mkdirAll(t, admin, r.linked)
	for path, data := range map[string]string{
		filepath.Join(admin, "commondir"):  "../..\n",
		filepath.Join(r.linked, ".git"):    "gitdir: " + admin + "\n",
		filepath.Join(r.store, "HEAD"):     "ref: refs/heads/main\n",
		filepath.Join(r.main, "README.md"): "top\n",
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func TestStoreRepositoriesFindsTheMainRepositoryOfALinkedWorktree(t *testing.T) {
	home := realTempDir(t)
	r := newRepositories(t, home)
	other := filepath.Join(home, "trees", "other")
	mkdirAll(t, filepath.Join(other, ".git"))
	p := &profile.Profile{VCSStore: true, Mounts: []profile.Mount{
		{Path: filepath.Join(home, "trees"), Mode: profile.ModeWrite},
		{Path: r.main, Mode: profile.ModeRead},
		{Path: filepath.Join(home, "hidden"), Mode: profile.ModeHide},
	}}
	mkdirAll(t, filepath.Join(home, "hidden", ".git"))
	got := storeRepositories(p, osHost{})
	if want := []string{r.main, other}; !sameElements(got, want) {
		t.Errorf("storeRepositories = %v, want %v once each, and nothing hidden", got, want)
	}
	p.VCSStore = false
	if got := storeRepositories(p, osHost{}); got != nil {
		t.Errorf("without [vcs] store: %v", got)
	}
}

func TestLinkedStoresAreAddedReadOnly(t *testing.T) {
	home := realTempDir(t)
	r := newRepositories(t, home)
	// Spare capacity would let an append write into the resolved profile.
	mounts := append(make([]profile.Mount, 0, 4), profile.Mount{Path: filepath.Join(home, "trees"), Mode: profile.ModeWrite})
	p := &profile.Profile{VCSStore: true, Mounts: mounts}
	got := withLinkedStores(p, osHost{})
	if want := append(slices.Clone(mounts), profile.Mount{Path: r.store, Mode: profile.ModeRead}); !slices.Equal(got.Mounts, want) {
		t.Errorf("mounts = %+v, want %+v", got.Mounts, want)
	}
	if len(p.Mounts) != 1 || mounts[:2][1] != (profile.Mount{}) {
		t.Errorf("the resolved profile changed: %+v", mounts[:2])
	}

	p.Mounts = append(p.Mounts, profile.Mount{Path: r.main, Mode: profile.ModeRead})
	if got := withLinkedStores(p, osHost{}); len(got.Mounts) != 2 {
		t.Errorf("a store the jail already sees was mounted again: %+v", got.Mounts)
	}
	p.VCSStore = false
	if got := withLinkedStores(p, osHost{}); got != p {
		t.Error("without [vcs] store the profile must stay as it is")
	}
}

func TestStartRepositoriesNeedsGitForTheVCSModule(t *testing.T) {
	s := newTestSession(t, nil)
	r := newRepositories(t, s.home)
	s.req.Profile.Mounts = []profile.Mount{{Path: r.main, Mode: profile.ModeRead}}
	if err := s.startRepositories(context.Background()); err != nil {
		t.Fatalf("without [vcs] store there is nothing to start: %v", err)
	}
	s.req.Profile.VCSStore = true
	if err := s.startRepositories(context.Background()); err == nil || !strings.Contains(err.Error(), "need git on the host") {
		t.Fatalf("err = %v", err)
	}
}

func TestFinishRecordSavesTheRecordAlsoWhenTheEndStepFails(t *testing.T) {
	paths := config.Paths{State: t.TempDir()}
	mkdirAll(t, paths.Backups())
	broken := t.TempDir()
	mkdirAll(t, filepath.Join(broken, ".git"))
	for _, c := range []struct {
		name    string
		rec     *vcs.Record
		failing bool
	}{
		{"no repositories", &vcs.Record{Session: "s1"}, false},
		{"a repository git cannot read", &vcs.Record{Session: "s2", Repos: []vcs.Repo{{Path: broken, GitDir: filepath.Join(broken, ".git")}}}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := FinishRecord(context.Background(), paths, vcs.Tools{Git: "/nonexistent/git"}, c.rec, &bytes.Buffer{}, io.Discard)
			if (err != nil) != c.failing {
				t.Fatalf("err = %v", err)
			}
			saved, err := vcs.Load(recordPath(paths, c.rec.Session))
			if err != nil || saved.Session != c.rec.Session {
				t.Fatalf("saved = %+v, %v", saved, err)
			}
		})
	}
}

func TestFinishRepositoriesWithoutARecordStopsTheWatchQuietly(t *testing.T) {
	s := newTestSession(t, nil)
	var out bytes.Buffer
	stopped := false
	s.repos.repairs = &repairLog{log: s.log}
	s.repos.stop = func() { stopped = true }
	s.finishRepositories(&out)
	if !stopped || out.Len() != 0 {
		t.Errorf("stopped = %v, out = %q", stopped, out.String())
	}
	if _, err := os.Stat(recordPath(s.deps.Paths, s.id)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a session without repositories wrote a record: %v", err)
	}
}

func TestRepairLogWritesEachRepairToTheAuditLogAndKeepsItForTheTerminal(t *testing.T) {
	s := newTestSession(t, nil)
	repairs := &repairLog{log: s.log}
	if _, err := repairs.Write([]byte("doriath: reset the commondir of wt\n")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.audit.String(), `"worktree-repair"`) || !strings.Contains(s.audit.String(), `"message":"doriath: reset the commondir of wt"`) {
		t.Errorf("audit:\n%s", s.audit)
	}
	if repairs.lines.String() != "doriath: reset the commondir of wt\n" {
		t.Errorf("terminal lines = %q", repairs.lines.String())
	}
}

func sameElements(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}

func TestTheEndOfASessionPutsBackTheStartValuesEarlierSessionsKept(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	repo := t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q", "-b", "main")
	run("commit", "-q", "--allow-empty", "-m", "first")
	first := run("rev-parse", "HEAD")
	paths := config.Paths{State: t.TempDir()}
	mkdirAll(t, paths.Backups())
	earlier := &vcs.Record{Session: "s1", Finished: true, Repos: []vcs.Repo{{
		Path: repo, GitDir: filepath.Join(repo, ".git"),
		Branches: map[string]string{"refs/heads/main": first}, Moved: []string{"refs/heads/main"},
	}}}
	if err := earlier.Save(recordPath(paths, "s1")); err != nil {
		t.Fatal(err)
	}
	if err := FinishRecord(context.Background(), paths, vcs.Tools{Git: "git"}, &vcs.Record{Session: "s2"}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got := run("rev-parse", vcs.BackupRef("s1", "refs/heads/main")); got != first {
		t.Fatalf("backup ref = %q, want %q", got, first)
	}
}

func TestTimeLeftWaitsForAMeasureAndRounds(t *testing.T) {
	for _, c := range []struct {
		elapsed time.Duration
		done    float64
		want    string
	}{
		{time.Second, 0.5, ""},
		{10 * time.Second, 0.01, ""},
		{10 * time.Second, 1, ""},
		{10 * time.Second, 0.5, "10 s"},
		{10 * time.Second, 0.9, "5 s"},
		{11 * time.Second, 0.5, "15 s"},
		{30 * time.Second, 0.25, "2 min"},
	} {
		got, ok := timeLeft(c.elapsed, c.done)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("timeLeft(%v, %v) = %q, %v, want %q", c.elapsed, c.done, got, ok, c.want)
		}
	}
}
