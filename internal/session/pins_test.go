package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/jailinit"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/proxy"
)

func TestOnlyThePinnedFileAndSystemCodeAreTrusted(t *testing.T) {
	tool := jailinit.FileID{Dev: 1, Ino: 2, Ctime: 3}
	ps := pins{programs: map[string]jailinit.FileID{"/home/u/bin/tool": tool}, code: map[string]uint64{"/home/u/bin/tool": 2, "/home/u/bin/libtool.so": 5}}
	libc := jailinit.MappedFile{Path: "/nix/store/x-glibc/lib/libc.so.6", Ino: 1}
	code := func(path string, ino uint64) jailinit.MappedFile { return jailinit.MappedFile{Path: path, Ino: ino} }
	for name, c := range map[string]struct {
		id   proxy.Identity
		want string
	}{
		"a system program":              {proxy.Identity{Exe: "/nix/store/x-git/bin/git", Code: []jailinit.MappedFile{code("/nix/store/x-git/bin/git", 8), libc}}, ""},
		"the pinned file":               {proxy.Identity{Exe: "/home/u/bin/tool", File: tool, Code: []jailinit.MappedFile{code("/home/u/bin/tool", 2), code("/home/u/bin/libtool.so", 5), libc}}, ""},
		"a library it brought, changed": {proxy.Identity{Exe: "/home/u/bin/tool", File: tool, Code: []jailinit.MappedFile{code("/home/u/bin/tool", 2), code("/home/u/bin/libtool.so", 6)}}, "runs code from /home/u/bin/libtool.so"},
		"another file at the path":      {proxy.Identity{Exe: "/home/u/bin/tool", File: jailinit.FileID{Dev: 1, Ino: 9, Ctime: 3}}, "is not the file it was"},
		"the file after a write":        {proxy.Identity{Exe: "/home/u/bin/tool", File: jailinit.FileID{Dev: 1, Ino: 2, Ctime: 4}}, "is not the file it was"},
		"a file the session made":       {proxy.Identity{Exe: "/home/u/bin/new"}, "is not a file that the profile names"},
		"a preloaded library":           {proxy.Identity{Exe: "/nix/store/x-git/bin/git", Code: []jailinit.MappedFile{code("/nix/store/x-git/bin/git", 8), code("/home/u/evil.so", 9), libc}}, "runs code from /home/u/evil.so"},
		"an unknown program":            {proxy.Identity{}, ""},
	} {
		got := ps.untrusted(c.id)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

func TestPinsFindTheProfilesFilesInMountsAndCaches(t *testing.T) {
	home := t.TempDir()
	cacheRoot := t.TempDir()
	tools := filepath.Join(home, "tools")
	cached := filepath.Join(cacheRoot, "home", "go", "bin")
	for _, f := range []struct{ path, body string }{
		{filepath.Join(tools, "fetch"), "\x7fELF"},
		{filepath.Join(tools, "script"), "#!/bin/sh\n"},
		{filepath.Join(cached, "gotool"), "\x7fELF"},
	} {
		if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.path, []byte(f.body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	p := &profile.Profile{
		Mounts: []profile.Mount{{Path: tools, Mode: profile.ModeWrite}},
		Caches: []profile.Cache{{Path: filepath.Join(home, "go")}},
		Egress: profile.Egress{Programs: []profile.ProgramEgress{{Binaries: []string{tools + "/*", filepath.Join(home, "go", "bin", "gotool")}}}},
	}
	ps, notes := pinBinaries(p, home, cacheRoot, []string{tools})
	if _, ok := ps.programs[filepath.Join(tools, "fetch")]; !ok || len(ps.programs) != 2 {
		t.Fatalf("pins = %v", ps)
	}
	if _, ok := ps.programs[filepath.Join(home, "go", "bin", "gotool")]; !ok {
		t.Errorf("the file in the profile's cache is not pinned: %v", ps)
	}
	if _, ok := ps.code[filepath.Join(tools, "script")]; !ok {
		t.Errorf("the files next to a pinned program are not recorded: %v", ps.code)
	}
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "script is a script") || !strings.Contains(joined, "the agent can write") {
		t.Errorf("notes:\n%s", joined)
	}
}
