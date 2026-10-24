package jail

import (
	"maps"
	"slices"
	"testing"

	"github.com/fnune/doriath/internal/profile"
)

// mode reports how binds expose dest: "read", "write", or "none" when no
// bind has it as its destination.
func mode(binds []Bind, dest string) string {
	i := slices.IndexFunc(binds, func(b Bind) bool { return b.Dest == dest })
	switch {
	case i < 0:
		return "none"
	case binds[i].ReadOnly:
		return "read"
	}
	return "write"
}

func access(binds []Bind, path string) string {
	got, depth := "read", -1
	for _, b := range binds {
		if within(path, b.Dest) && len(b.Dest) >= depth {
			got, depth = "write", len(b.Dest)
			if b.ReadOnly {
				got = "read"
			}
		}
	}
	return got
}

func expectAccess(t *testing.T, binds []Bind, want map[string]string) {
	t.Helper()
	for _, p := range slices.Sorted(maps.Keys(want)) {
		if got := access(binds, p); got != want[p] {
			t.Errorf("%s: %s, want %s", p, got, want[p])
		}
	}
}

func storeBinds(repo string, h Host) []Bind {
	g := &guards{host: h}
	g.store(repo)
	return g.binds
}

func expectModes(t *testing.T, binds []Bind, want map[string]string) {
	t.Helper()
	for _, p := range slices.Sorted(maps.Keys(want)) {
		if got := mode(binds, p); got != want[p] {
			t.Errorf("%s: %s, want %s", p, got, want[p])
		}
	}
}

// storeHost is a colocated repository at /home/u/repo with a linked
// worktree, a pack, an alternates guard and jj's own store.
func storeHost() fakeHost {
	const repo = "/home/u/repo"
	h := fakeHost{}
	for p, k := range map[string]string{
		"":                                 "dir",
		"/.git":                            "dir",
		"/.git/HEAD":                       "file",
		"/.git/config":                     "file",
		"/.git/hooks":                      "dir",
		"/.git/objects":                    "dir",
		"/.git/objects/info":               "dir",
		"/.git/objects/info/alternates":    "file",
		"/.git/objects/pack":               "dir",
		"/.git/objects/pack/p.pack":        "file",
		"/.git/refs":                       "dir",
		"/.git/logs":                       "dir",
		"/.git/worktrees":                  "dir",
		"/.git/worktrees/wt":               "dir",
		"/.git/worktrees/wt/commondir":     "file",
		"/.git/worktrees/wt/gitdir":        "file",
		"/.git/worktrees/wt/HEAD":          "file",
		"/.jj":                             "dir",
		"/.jj/working_copy":                "dir",
		"/.jj/repo":                        "dir",
		"/.jj/repo/config.toml":            "file",
		"/.jj/repo/index":                  "dir",
		"/.jj/repo/op_heads":               "dir",
		"/.jj/repo/op_store":               "dir",
		"/.jj/repo/store":                  "dir",
		"/.jj/repo/store/extra":            "dir",
		"/.jj/repo/store/git":              "dir",
		"/.jj/repo/store/git/objects":      "dir",
		"/.jj/repo/store/git/refs":         "dir",
		"/.jj/repo/store/git/config":       "file",
		"/.jj/repo/git_import_export.lock": "file",
	} {
		h[repo+p] = k
	}
	return h
}

func TestAStoreThatManyWorktreesShareIsGuardedOnce(t *testing.T) {
	const repo = "/home/u/repo"
	g := &guards{host: storeHost()}
	g.store(repo)
	once := len(g.binds)
	for range 50 {
		g.store(repo)
	}
	if got := len(uniqueBinds(g.binds)); got != once {
		t.Errorf("binds = %d after 51 visits of one store, %d after one: bubblewrap takes at most 9000 arguments", got, once)
	}
}

func TestStoreBindsKeepWhatDecidesWhatRunsReadOnly(t *testing.T) {
	const repo = "/home/u/repo"
	expectAccess(t, storeBinds(repo, storeHost()), map[string]string{
		repo + "/.git":                            "write",
		repo + "/.git/packed-refs.lock":           "write",
		repo + "/.git/index.lock":                 "write",
		repo + "/.git/HEAD":                       "write",
		repo + "/.git/objects":                    "write",
		repo + "/.git/refs":                       "write",
		repo + "/.git/config":                     "read",
		repo + "/.git/hooks":                      "read",
		repo + "/.git/objects/info/alternates":    "read",
		repo + "/.git/objects/pack/p.pack":        "read",
		repo + "/.git/worktrees/wt/commondir":     "read",
		repo + "/.git/worktrees/wt/gitdir":        "read",
		repo + "/.git/worktrees/wt/HEAD":          "write",
		repo + "/.jj/working_copy":                "write",
		repo + "/.jj/repo":                        "read",
		repo + "/.jj/repo/config.toml":            "read",
		repo + "/.jj/repo/index":                  "write",
		repo + "/.jj/repo/op_heads":               "write",
		repo + "/.jj/repo/op_store":               "write",
		repo + "/.jj/repo/store/extra":            "write",
		repo + "/.jj/repo/git_import_export.lock": "write",
		repo + "/.jj/repo/store/git/objects":      "write",
		repo + "/.jj/repo/store/git/config":       "read",
	})
}

func TestStoreBindsOfAMountedStore(t *testing.T) {
	const repo = "/home/u/repo"
	h := storeHost()
	expectAccess(t, storeBinds(repo+"/.git", h), map[string]string{
		repo + "/.git/objects":                "write",
		repo + "/.git/config":                 "read",
		repo + "/.git/objects/pack/p.pack":    "read",
		repo + "/.git/worktrees/wt/commondir": "read",
		repo + "/.jj/repo/index":              "read",
	})
	expectAccess(t, storeBinds(repo+"/.jj/repo", h), map[string]string{
		repo + "/.jj/repo/index":                  "write",
		repo + "/.jj/repo/git_import_export.lock": "write",
		repo + "/.jj/repo/store/git/objects":      "write",
		repo + "/.jj/repo/store/git/config":       "read",
		repo + "/.jj/working_copy":                "read",
		repo + "/.git/objects":                    "read",
	})
}

func TestPlanBindsStoresOnlyWhenTheProfileAsks(t *testing.T) {
	h := host()
	for p, k := range storeHost() {
		h[p] = k
	}
	p := testProfile()
	p.Mounts = append(p.Mounts, profile.Mount{Path: "/home/u/repo", Mode: profile.ModeRead})
	s, err := Plan(p, layout(), opts(), held(p, h))
	if err != nil {
		t.Fatal(err)
	}
	if got := access(s.Binds, "/home/u/repo/.git/objects"); got != "read" {
		t.Errorf("without [vcs] store the store stays read-only: %s", got)
	}
	p.VCSStore = true
	s, err = Plan(p, layout(), opts(), held(p, h))
	if err != nil {
		t.Fatal(err)
	}
	if got := access(s.Binds, "/home/u/repo/.git/objects"); got != "write" {
		t.Errorf("with [vcs] store the objects are writable: %s", got)
	}
	idx := func(dest string) int { return slices.IndexFunc(s.Binds, func(b Bind) bool { return b.Dest == dest }) }
	if idx("/home/u/repo") > idx("/home/u/repo/.git") || idx("/home/u/repo/.git") > idx("/home/u/repo/.git/config") {
		t.Error("each bind must come before the binds inside it")
	}
}

func TestWritableRepositoriesKeepTheirControlFilesReadOnly(t *testing.T) {
	const repo = "/home/u/repo"
	h := host()
	for p, k := range storeHost() {
		h[p] = k
	}
	h[repo+"/.jj/repo/store/git/hooks"] = "dir"
	p := testProfile()
	p.Mounts = append(p.Mounts, profile.Mount{Path: repo, Mode: profile.ModeWrite})
	s, err := Plan(p, layout(), opts(), held(p, h))
	if err != nil {
		t.Fatal(err)
	}
	expectModes(t, s.Binds, map[string]string{
		repo:                                  "write",
		repo + "/.git/config":                 "read",
		repo + "/.git/hooks":                  "read",
		repo + "/.git/worktrees/wt/commondir": "read",
		repo + "/.git/worktrees/wt/gitdir":    "read",
		repo + "/.git/objects/pack/p.pack":    "read",
		repo + "/.jj/repo/config.toml":        "read",
		repo + "/.jj/repo/store/git/config":   "read",
		repo + "/.jj/repo/store/git/hooks":    "read",
	})
}

func TestAJJLockThatHostJJDeletedIsHeldAgainWhileJJRepoStaysReadOnly(t *testing.T) {
	const repo = "/home/u/repo"
	h := storeHost()
	delete(h, repo+"/.jj/repo/git_import_export.lock")
	g := &guards{host: h}
	g.store(repo)
	if !slices.ContainsFunc(g.missing, func(p Placeholder) bool { return p.Path == repo+"/.jj/repo/git_import_export.lock" && !p.Dir }) {
		t.Errorf("placeholders = %+v", g.missing)
	}
	if mode(g.binds, repo+"/.jj/repo") != "none" {
		t.Error(".jj/repo became writable, where the agent could plant a config.toml that host jj copies into your own config")
	}
}

func TestTheParentsOfGuardedFilesAreMountPointsInWriteMounts(t *testing.T) {
	const repo = "/home/u/repo"
	h := host()
	for p, k := range storeHost() {
		h[p] = k
	}
	h[repo+"/.claude"] = "dir"
	h[repo+"/.claude/settings.json"] = "file"
	h[repo+"/config"] = "dir"
	h[repo+"/config/secrets"] = "dir"
	h[repo+"/config/secrets/.env"] = "file"
	p := testProfile()
	p.Mounts = append(p.Mounts,
		profile.Mount{Path: repo, Mode: profile.ModeWrite},
		profile.Mount{Path: repo + "/.claude/settings.json", Mode: profile.ModeRead},
		profile.Mount{Path: repo + "/config/secrets/.env", Mode: profile.ModeHide},
	)
	s, err := Plan(p, layout(), opts(), held(p, h))
	if err != nil {
		t.Fatal(err)
	}
	expectModes(t, s.Binds, map[string]string{
		repo + "/.git":                 "write",
		repo + "/.git/objects":         "write",
		repo + "/.git/objects/pack":    "write",
		repo + "/.git/worktrees/wt":    "write",
		repo + "/.jj":                  "write",
		repo + "/.jj/repo":             "write",
		repo + "/.claude":              "write",
		repo + "/config":               "write",
		repo + "/config/secrets":       "write",
		repo + "/config/secrets/.env":  "read",
		repo + "/.git/hooks":           "read",
		repo + "/.jj/repo/config.toml": "read",
	})
	for _, b := range s.Binds {
		if b.Dest == repo+"/.git" && b.Source != b.Dest {
			t.Errorf("the pin of %s binds %s, want the directory itself", b.Dest, b.Source)
		}
	}
	idx := func(dest string) int { return slices.IndexFunc(s.Binds, func(b Bind) bool { return b.Dest == dest }) }
	if idx(repo) > idx(repo+"/.git") || idx(repo+"/.git") > idx(repo+"/.git/hooks") {
		t.Error("each pin must come after the mount that holds it and before the guards inside it")
	}
}

func TestNothingIsPinnedUnderAReadOnlyMount(t *testing.T) {
	h := host()
	h["/home/u/Development/project/site/.git"] = "dir"
	h["/home/u/Development/project/site/.git/config"] = "file"
	p := testProfile()
	s, err := Plan(p, layout(), opts(), held(p, h))
	if err != nil {
		t.Fatal(err)
	}
	if got := mode(s.Binds, "/home/u/Development/project/site/.git"); got != "none" {
		t.Errorf("a read-only mount needs no pins, got %s", got)
	}
}

func TestBetweenListsTheDirectoriesBelowTheRootAndAboveThePath(t *testing.T) {
	for _, c := range []struct {
		root, path string
		want       []string
	}{
		{"/r", "/r/.git/hooks", []string{"/r/.git"}},
		{"/r", "/r/.git/objects/pack/p.pack", []string{"/r/.git", "/r/.git/objects", "/r/.git/objects/pack"}},
		{"/r", "/r/.envrc", nil},
		{"/r", "/other/.git/hooks", nil},
		{"/", "/r/.git/hooks", []string{"/r", "/r/.git"}},
	} {
		if got := Between(c.root, c.path); !slices.Equal(got, c.want) {
			t.Errorf("Between(%s, %s) = %v, want %v", c.root, c.path, got, c.want)
		}
	}
}
