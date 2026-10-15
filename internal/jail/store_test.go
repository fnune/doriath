package jail

import (
	"maps"
	"slices"
	"testing"

	"github.com/fnune/girdle/internal/profile"
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

func TestStoreBindsMakeOnlyTheDataWritable(t *testing.T) {
	const repo = "/home/u/repo"
	expectModes(t, storeBinds(repo, storeHost()), map[string]string{
		repo + "/.git":                            "none",
		repo + "/.git/config":                     "none",
		repo + "/.git/hooks":                      "none",
		repo + "/.git/objects":                    "write",
		repo + "/.git/refs":                       "write",
		repo + "/.git/logs":                       "write",
		repo + "/.git/worktrees":                  "write",
		repo + "/.git/lfs":                        "none",
		repo + "/.git/objects/info/alternates":    "read",
		repo + "/.git/objects/pack/p.pack":        "read",
		repo + "/.git/worktrees/wt/commondir":     "read",
		repo + "/.git/worktrees/wt/gitdir":        "read",
		repo + "/.git/worktrees/wt/HEAD":          "none",
		repo + "/.jj/working_copy":                "write",
		repo + "/.jj/repo":                        "none",
		repo + "/.jj/repo/config.toml":            "none",
		repo + "/.jj/repo/index":                  "write",
		repo + "/.jj/repo/op_heads":               "write",
		repo + "/.jj/repo/op_store":               "write",
		repo + "/.jj/repo/store/extra":            "write",
		repo + "/.jj/repo/git_import_export.lock": "write",
		repo + "/.jj/repo/store/git/objects":      "write",
		repo + "/.jj/repo/store/git/config":       "none",
	})
}

func TestStoreBindsOfAMountedStore(t *testing.T) {
	const repo = "/home/u/repo"
	h := storeHost()
	expectModes(t, storeBinds(repo+"/.git", h), map[string]string{
		repo + "/.git/objects":                "write",
		repo + "/.git/objects/pack/p.pack":    "read",
		repo + "/.git/worktrees/wt/commondir": "read",
		repo + "/.jj/repo/index":              "none",
	})
	expectModes(t, storeBinds(repo+"/.jj/repo", h), map[string]string{
		repo + "/.jj/repo/index":                  "write",
		repo + "/.jj/repo/git_import_export.lock": "write",
		repo + "/.jj/repo/store/git/objects":      "write",
		repo + "/.jj/working_copy":                "none",
		repo + "/.git/objects":                    "none",
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
	if got := mode(s.Binds, "/home/u/repo/.git/objects"); got != "none" {
		t.Errorf("without the vcs module the store stays read-only: %s", got)
	}
	p.VCSStore = true
	s, err = Plan(p, layout(), opts(), held(p, h))
	if err != nil {
		t.Fatal(err)
	}
	if got := mode(s.Binds, "/home/u/repo/.git/objects"); got != "write" {
		t.Errorf("with the vcs module the objects are writable: %s", got)
	}
	idx := func(dest string) int { return slices.IndexFunc(s.Binds, func(b Bind) bool { return b.Dest == dest }) }
	if idx("/home/u/repo") > idx("/home/u/repo/.git/objects") {
		t.Error("the read-only mount must come before the store binds inside it")
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
