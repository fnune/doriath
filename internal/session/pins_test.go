package session

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/jailinit"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/proxy"
)

func TestOnlyThePinnedFileAndSystemCodeAreTrusted(t *testing.T) {
	tool := jailinit.FileID{Dev: 1, Ino: 2, Ctime: 3}
	ps := pins{programs: map[string]jailinit.FileID{"/home/u/bin/tool": tool}, code: map[string]jailinit.FileID{"/home/u/bin/tool": tool, "/home/u/bin/libtool.so": {Dev: 1, Ino: 5, Ctime: 3}}}
	libc := jailinit.MappedFile{Path: "/nix/store/x-glibc/lib/libc.so.6", Ino: 1}
	code := func(path string, ino uint64) jailinit.MappedFile {
		return jailinit.MappedFile{Path: path, Ino: ino, File: jailinit.FileID{Dev: 1, Ino: ino, Ctime: 3}}
	}
	for name, c := range map[string]struct {
		id   proxy.Identity
		want string
	}{
		"a system program":              {proxy.Identity{Exe: "/nix/store/x-git/bin/git", Code: []jailinit.MappedFile{code("/nix/store/x-git/bin/git", 8), libc}}, ""},
		"the pinned file":               {proxy.Identity{Exe: "/home/u/bin/tool", File: tool, Code: []jailinit.MappedFile{code("/home/u/bin/tool", 2), code("/home/u/bin/libtool.so", 5), libc}}, ""},
		"a library it brought, changed": {proxy.Identity{Exe: "/home/u/bin/tool", File: tool, Code: []jailinit.MappedFile{code("/home/u/bin/tool", 2), code("/home/u/bin/libtool.so", 6)}}, "runs code from /home/u/bin/libtool.so"},
		"a library written in place":    {proxy.Identity{Exe: "/home/u/bin/tool", File: tool, Code: []jailinit.MappedFile{code("/home/u/bin/tool", 2), {Path: "/home/u/bin/libtool.so", Ino: 5, File: jailinit.FileID{Dev: 1, Ino: 5, Ctime: 4}}}}, "runs code from /home/u/bin/libtool.so"},
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

func TestAStorePathAddedAfterTheStartGetsNoCredentialWithTheNixDaemon(t *testing.T) {
	ps := pins{store: map[string]struct{}{"x-gh-2.0": {}}}
	known := proxy.Identity{Exe: "/nix/store/x-gh-2.0/bin/gh"}
	added := proxy.Identity{Exe: "/nix/store/y-gh/bin/gh"}
	preload := proxy.Identity{Exe: "/nix/store/x-gh-2.0/bin/gh", Code: []jailinit.MappedFile{{Path: "/nix/store/y-evil/lib/evil.so", Ino: 1}}}
	if got := ps.untrusted(known); got != "" {
		t.Errorf("a path from the start: %q", got)
	}
	for name, id := range map[string]proxy.Identity{"a program": added, "a library": preload} {
		if got := ps.untrusted(id); got == "" {
			t.Errorf("%s that the session added to the store is trusted", name)
		}
	}
	if got := (pins{}).untrusted(added); got != "" {
		t.Errorf("without the nix-daemon module the store is read-only, but %q", got)
	}
}

func TestASystemPathThatTheAgentCanWriteIsNotASystemPath(t *testing.T) {
	ps := pins{programs: map[string]jailinit.FileID{}, writable: []string{"/opt/project"}}
	if got := ps.untrusted(proxy.Identity{Exe: "/opt/project/bin/gh"}); got == "" {
		t.Error("a program in a writable folder under /opt is trusted by its name")
	}
	if got := ps.untrusted(proxy.Identity{Exe: "/opt/tools/bin/gh"}); got != "" {
		t.Errorf("a program in a read-only folder under /opt: %q", got)
	}
	if got := ps.untrusted(proxy.Identity{Exe: "/usr/bin/gh", Code: []jailinit.MappedFile{{Path: "/opt/project/lib/evil.so", Ino: 1}}}); got == "" {
		t.Error("a library in a writable folder under /opt is trusted")
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

func TestAProgramsLibraryFoldersArePinnedWithinItsInstallPrefixOnly(t *testing.T) {
	got := libraryFolders([]string{"$ORIGIN", "$ORIGIN/../lib", "${ORIGIN}/../lib/server", "/usr/lib", "$ORIGIN/../..", "$ORIGIN/..", "$ORIGIN/../lib"})
	if want := []string{"../lib", "../lib/server"}; !slices.Equal(got, want) {
		t.Errorf("folders = %v, want %v", got, want)
	}
}

func writeELF(t *testing.T, dynamicSize uint64) string {
	t.Helper()
	const strtabOff, dynamicOff = 64, 128
	shoff := dynamicOff + dynamicSize
	path := filepath.Join(t.TempDir(), "tool")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	header := elf.Header64{Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: 1, Shoff: shoff, Ehsize: 64, Shentsize: 64, Shnum: 3}
	copy(header.Ident[:], elf.ELFMAG)
	header.Ident[elf.EI_CLASS], header.Ident[elf.EI_DATA], header.Ident[elf.EI_VERSION] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1
	strtab := "\x00$ORIGIN/../lib\x00"
	sections := []elf.Section64{
		{},
		{Type: uint32(elf.SHT_DYNAMIC), Off: dynamicOff, Size: dynamicSize, Link: 2, Entsize: 16},
		{Type: uint32(elf.SHT_STRTAB), Off: strtabOff, Size: uint64(len(strtab))},
	}
	write := func(off int64, data any) {
		if _, err := f.Seek(off, 0); err != nil {
			t.Fatal(err)
		}
		if err := binary.Write(f, binary.LittleEndian, data); err != nil {
			t.Fatal(err)
		}
	}
	write(0, header)
	write(strtabOff, []byte(strtab))
	write(dynamicOff, []elf.Dyn64{{Tag: int64(elf.DT_RUNPATH), Val: 1}})
	write(int64(shoff), sections)
	return path
}

func TestAnOversizedDynamicSectionIsNotRead(t *testing.T) {
	if got := runpaths(writeELF(t, 32)); !slices.Equal(got, []string{"$ORIGIN/../lib"}) {
		t.Fatalf("runpaths = %q", got)
	}
	if got := runpaths(writeELF(t, maxDynamicData+16)); got != nil {
		t.Fatalf("runpaths = %q, want none", got)
	}
}
