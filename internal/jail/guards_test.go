package jail

import (
	"slices"
	"testing"
)

type sortedHost struct{ fakeHost }

func (h sortedHost) Entries(dir string) []string {
	return slices.Sorted(slices.Values(h.fakeHost.Entries(dir)))
}

func TestPlanRejectsRelativeDirectories(t *testing.T) {
	o := opts()
	o.Cwd = "Development/project"
	if _, err := Plan(testProfile(), layout(), o, host()); err == nil {
		t.Error("a relative working directory must be an error")
	}
	o = opts()
	o.Home = "u"
	if _, err := Plan(testProfile(), layout(), o, host()); err == nil {
		t.Error("a relative home must be an error")
	}
}

func TestArgsPassFileDescriptorsOnlyWhenSet(t *testing.T) {
	s := Spec{Hostname: "girdle-x", Cwd: "/", Command: []string{"true"}}
	for _, flag := range []string{"--seccomp", "--info-fd"} {
		if slices.Contains(s.Args(), flag) {
			t.Errorf("%s without a file descriptor", flag)
		}
	}
	s.SeccompFD, s.InfoFD = 7, 9
	args := s.Args()
	for flag, fd := range map[string]string{"--seccomp": "7", "--info-fd": "9"} {
		i := slices.Index(args, flag)
		if i < 0 || i+1 >= len(args) || args[i+1] != fd {
			t.Errorf("%s %s missing from %q", flag, fd, args)
		}
	}
}

func TestBindsOfEqualDepthKeepTheirOrder(t *testing.T) {
	binds := []Bind{
		{Source: "/first", Dest: "/home/u/a"},
		{Source: "/x", Dest: "/home/u/a/deep"},
		{Source: "/second", Dest: "/home/u/a"},
		{Source: "/y", Dest: "/home"},
	}
	mountParentsBeforeChildren(binds)
	var got []string
	for _, b := range binds {
		got = append(got, b.Source)
	}
	if want := []string{"/y", "/first", "/second", "/x"}; !slices.Equal(got, want) {
		t.Fatalf("order = %q, want %q", got, want)
	}
}

func TestRepositoryAfterASkippedDirectoryIsGuarded(t *testing.T) {
	h := host()
	root := "/home/u/Development/project"
	for p, k := range map[string]string{
		root + "/.cache":            "dir",
		root + "/node_modules":      "dir",
		root + "/zrepo":             "dir",
		root + "/zrepo/.git":        "dir",
		root + "/zrepo/.git/config": "file",
	} {
		h[p] = k
	}
	s, err := Plan(testProfile(), layout(), opts(), sortedHost{held(testProfile(), h)})
	if err != nil {
		t.Fatal(err)
	}
	if mode(s.Binds, root+"/zrepo/.git/config") != "read" {
		t.Fatal("the repository listed after node_modules must be guarded")
	}
}

func TestSubmoduleStoresWithSlashedNamesAreCovered(t *testing.T) {
	git := "/home/u/repo/.git"
	foo := git + "/modules/libs/foo"
	h := fakeHost{
		git:                          "dir",
		git + "/HEAD":                "file",
		git + "/objects":             "dir",
		git + "/modules":             "dir",
		git + "/modules/libs":        "dir",
		foo:                          "dir",
		foo + "/HEAD":                "file",
		foo + "/config":              "file",
		foo + "/objects":             "dir",
		foo + "/objects/pack":        "dir",
		foo + "/objects/pack/p.pack": "file",
	}
	g := &guards{host: h}
	g.store(git)
	g.gitDir(git, git, 0)
	expectModes(t, g.binds, map[string]string{
		foo + "/objects":             "write",
		foo + "/objects/pack/p.pack": "read",
		foo + "/config":              "read",
	})
}
