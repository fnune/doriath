package jail

import (
	"slices"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/profile"
)

func TestExtendMakesAWritableRepositoryWithItsGuards(t *testing.T) {
	repo := "/home/u/other"
	h := fakeHost{repo: "dir", repo + "/.git": "dir", repo + "/.git/config": "file", repo + "/.envrc": "file", repo + "/secrets": "dir"}
	p := &profile.Profile{Mounts: []profile.Mount{
		{Path: repo, Mode: profile.ModeWrite},
		{Path: repo + "/.envrc", Mode: profile.ModeRead},
		{Path: repo + "/secrets", Mode: profile.ModeHide},
	}}
	ext, err := Extend(p, held(p, h))
	if err != nil {
		t.Fatal(err)
	}
	if len(ext.Write) != 1 || ext.Write[0].Path != repo {
		t.Fatalf("writes = %+v", ext.Write)
	}
	for _, guard := range []string{repo + "/.envrc", repo + "/.git/config", repo + "/.git/hooks"} {
		if !slices.Contains(ext.Write[0].Guards, guard) {
			t.Errorf("guards %v lack %s", ext.Write[0].Guards, guard)
		}
	}
	if len(ext.Read) != 0 || !slices.Equal(ext.Hide, []string{repo + "/secrets"}) {
		t.Errorf("reads %v, hides %v", ext.Read, ext.Hide)
	}
}

func TestExtendShowsAReadOnlyCheckoutAndWritesItsStore(t *testing.T) {
	repo := "/home/u/other"
	h := fakeHost{repo: "dir", repo + "/.git": "dir", repo + "/.git/config": "file", repo + "/.git/objects": "dir", repo + "/.git/refs": "dir"}
	p := &profile.Profile{VCSStore: true, Mounts: []profile.Mount{{Path: repo, Mode: profile.ModeRead}}}
	ext, err := Extend(p, held(p, h))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ext.Read, []string{repo}) {
		t.Errorf("reads = %v", ext.Read)
	}
	if !slices.ContainsFunc(ext.Write, func(w Promotion) bool {
		return w.Path == repo+"/.git" && slices.Contains(w.Guards, repo+"/.git/config")
	}) {
		t.Errorf("writes = %+v, want the store with its config read-only", ext.Write)
	}
	for i := 1; i < len(ext.Write); i++ {
		if len(ext.Write[i].Path) < len(ext.Write[i-1].Path) {
			t.Errorf("writes are not outermost first: %+v", ext.Write)
		}
	}
}

func TestExtendRefusesWhatWouldStopASession(t *testing.T) {
	p := &profile.Profile{Mounts: []profile.Mount{{Path: "/home/u/other/docs", Mode: profile.ModeRead}}}
	if _, err := Extend(p, fakeHost{}); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("a missing mount: %v", err)
	}
}
