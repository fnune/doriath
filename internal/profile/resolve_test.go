package profile

import (
	"strings"
	"testing"
)

func resolve(t *testing.T, p *Profile, start Start) []Mount {
	t.Helper()
	r, err := p.Resolve(start, "/home/u")
	if err != nil {
		t.Fatal(err)
	}
	return r.Mounts
}

func mode(mounts []Mount, path string) Mode {
	for _, m := range mounts {
		if m.Path == path {
			return m.Mode
		}
	}
	return ""
}

var inRepo = Start{Current: "/home/u/src/app/pkg", Repository: "/home/u/src/app"}

func TestCurrentIsReadableByDefault(t *testing.T) {
	got := resolve(t, &Profile{}, inRepo)
	if mode(got, "/home/u/src/app/pkg") != ModeRead || mode(got, "/home/u/src/app") != "" {
		t.Fatalf("mounts = %+v", got)
	}
}

func TestRepositoryIsReadableWithTheVCSModule(t *testing.T) {
	got := resolve(t, &Profile{VCSStore: true}, inRepo)
	if mode(got, "/home/u/src/app") != ModeRead {
		t.Fatalf("mounts = %+v", got)
	}
	if got := resolve(t, &Profile{VCSStore: true}, Start{Current: "/home/u/notes"}); mode(got, "/home/u/notes") != ModeRead || len(got) != 1 {
		t.Fatalf("outside a repository: %+v", got)
	}
}

func TestDefaultsYieldToTheProfile(t *testing.T) {
	p := &Profile{VCSStore: true, Mounts: []Mount{{Path: "{repository}", Mode: ModeWrite}, {Path: "{current}", Mode: ModeHide}}}
	got := resolve(t, p, inRepo)
	if mode(got, "/home/u/src/app") != ModeWrite || mode(got, "/home/u/src/app/pkg") != ModeHide {
		t.Fatalf("mounts = %+v", got)
	}
	if len(got) != 2 {
		t.Fatalf("a default must not stay beside the entry it yields to: %+v", got)
	}
}

func TestDefaultsYieldToAnEntryAbove(t *testing.T) {
	p := &Profile{VCSStore: true, Mounts: []Mount{{Path: "/home/u/src", Mode: ModeWrite}}}
	got := resolve(t, p, inRepo)
	if len(got) != 1 || got[0].Mode != ModeWrite {
		t.Fatalf("a writable parent must not be cut by a read-only default below it: %+v", got)
	}
}

func TestEntriesForTheSamePathKeepTheLowerPrivilege(t *testing.T) {
	p := &Profile{Mounts: []Mount{{Path: "{repository}", Mode: ModeWrite}, {Path: "/home/u/src/app", Mode: ModeRead}}}
	if got := resolve(t, p, inRepo); mode(got, "/home/u/src/app") != ModeRead {
		t.Fatalf("mounts = %+v", got)
	}
}

func TestRepositoryEntriesAreSkippedOutsideARepository(t *testing.T) {
	p := &Profile{Mounts: []Mount{{Path: "{repository}/.claude/worktrees", Mode: ModeWrite}}}
	got := resolve(t, p, Start{Current: "/home/u/notes"})
	if len(got) != 1 || got[0].Path != "/home/u/notes" {
		t.Fatalf("mounts = %+v", got)
	}
	got = resolve(t, p, inRepo)
	if m := got[len(got)-1]; m.Path != "/home/u/src/app/.claude/worktrees" || !m.Create {
		t.Fatalf("a writable entry inside the repository is created when missing: %+v", got)
	}
}

func TestStartingInTheHomeIsRefused(t *testing.T) {
	for _, start := range []Start{{Current: "/home/u"}, {Current: "/"}, {Current: "/home"}} {
		if _, err := (&Profile{}).Resolve(start, "/home/u"); err == nil || !strings.Contains(err.Error(), "would see") {
			t.Errorf("%s: %v", start.Current, err)
		}
	}
	p := &Profile{Mounts: []Mount{{Path: "{repository}", Mode: ModeRead}}}
	if _, err := p.Resolve(Start{Current: "/home/u/x", Repository: "/home/u"}, "/home/u"); err == nil {
		t.Error("a home directory that is a repository must still be refused")
	}
}

func TestFindRepository(t *testing.T) {
	exists := func(p string) bool { return p == "/home/u/src/app/.git" || p == "/home/u/jj/.jj" }
	for dir, want := range map[string]string{
		"/home/u/src/app/pkg/x": "/home/u/src/app",
		"/home/u/src/app":       "/home/u/src/app",
		"/home/u/jj/sub":        "/home/u/jj",
		"/home/u/notes":         "",
	} {
		if got := FindRepository(dir, exists); got != want {
			t.Errorf("FindRepository(%s) = %q, want %q", dir, got, want)
		}
	}
}

func TestTheSameMountTwiceKeepsTheLesserAccess(t *testing.T) {
	for _, order := range [][2]Mode{{ModeWrite, ModeRead}, {ModeRead, ModeWrite}} {
		mounts := mergeKeepingLessAccess(nil, Mount{Path: "/p", Mode: order[0]})
		mounts = mergeKeepingLessAccess(mounts, Mount{Path: "/p", Mode: order[1]})
		if len(mounts) != 1 || mounts[0].Mode != ModeRead {
			t.Errorf("%v then %v = %+v", order[0], order[1], mounts)
		}
	}
}
