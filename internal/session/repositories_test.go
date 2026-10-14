package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

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
		t.Errorf("without the vcs module: %v", got)
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
		t.Error("without the vcs module the profile must stay as it is")
	}
}

func TestStartRepositoriesNeedsGitForTheVCSModule(t *testing.T) {
	s := newTestSession(t, nil)
	r := newRepositories(t, s.home)
	s.req.Profile.Mounts = []profile.Mount{{Path: r.main, Mode: profile.ModeRead}}
	if err := s.startRepositories(context.Background()); err != nil {
		t.Fatalf("without the vcs module there is nothing to start: %v", err)
	}
	s.req.Profile.VCSStore = true
	if err := s.startRepositories(context.Background()); err == nil || !strings.Contains(err.Error(), "needs git on the host") {
		t.Fatalf("err = %v", err)
	}
}

func TestFinishRecordSavesTheRecordAlsoWhenTheEndStepFails(t *testing.T) {
	paths := config.Paths{State: t.TempDir()}
	mkdirAll(t, paths.Backups())
	for _, c := range []struct {
		name    string
		rec     *vcs.Record
		failing bool
	}{
		{"no repositories", &vcs.Record{Session: "s1"}, false},
		{"a repository git cannot read", &vcs.Record{Session: "s2", Repos: []vcs.Repo{{Path: "/nonexistent", GitDir: "/nonexistent/.git"}}}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := FinishRecord(context.Background(), paths, vcs.Tools{Git: "/nonexistent/git"}, c.rec, &bytes.Buffer{})
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
	s.unwatch = func(io.Writer) { stopped = true }
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
