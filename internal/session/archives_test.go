package session

import (
	"archive/zip"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/jailinit"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/proxy"
)

func library(tag string) string {
	header := make([]byte, 64+56)
	copy(header, "\x7fELF")
	header[4], header[5], header[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(header[16:], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(header[18:], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(header[20:], 1)
	binary.LittleEndian.PutUint64(header[32:], 64)
	binary.LittleEndian.PutUint16(header[52:], 64)
	binary.LittleEndian.PutUint16(header[54:], 56)
	binary.LittleEndian.PutUint16(header[56:], 1)
	body := header[:64]
	text := []byte(tag)
	phdr := make([]byte, 56)
	binary.LittleEndian.PutUint32(phdr[0:], uint32(elf.PT_LOAD))
	binary.LittleEndian.PutUint32(phdr[4:], uint32(elf.PF_R|elf.PF_X))
	binary.LittleEndian.PutUint64(phdr[32:], uint64(64+56+len(text)))
	binary.LittleEndian.PutUint64(phdr[40:], uint64(64+56+len(text)))
	return string(body) + string(phdr) + string(text)
}

var jni = library("the jni library")

func writeZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(out)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

const (
	mapStart = 0x10000
	fakePID  = 4242
)

func fakeMappedLibrary(t *testing.T, root, body string) jailinit.MappedFile {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(fakePID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pages := make([]byte, alignUp(uint64(len(body)), uint64(os.Getpagesize())))
	copy(pages, body)
	mem, err := os.Create(filepath.Join(dir, "mem"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mem.Close() }()
	if _, err := mem.WriteAt(pages, mapStart); err != nil {
		t.Fatal(err)
	}
	return jailinit.MappedFile{
		Path:  "/tmp/bazel-jni.x/libunix_jni.so (deleted)",
		Ino:   7,
		Range: fmt.Sprintf("%x-%x", mapStart, mapStart+len(pages)),
	}
}

func archiveProfile(home string) *profile.Profile {
	return &profile.Profile{
		Mounts:       []profile.Mount{{Path: filepath.Join(home, ".cache", "bazel"), Mode: profile.ModeWrite}},
		CodeArchives: []string{filepath.Join(home, ".cache", "bazel", "install", "*", "A-server.jar")},
	}
}

func TestPinnedArchivesTrustTheNativeLibrariesTheyShipEvenAfterTheCopyIsDeleted(t *testing.T) {
	home, proc := t.TempDir(), t.TempDir()
	jar := filepath.Join(home, ".cache", "bazel", "install", "abc", "A-server.jar")
	writeZip(t, jar, map[string]string{
		"main/native/libunix_jni.so": jni,
		"data/not-elf.so":            "plain text",
		"lib/readme.txt":             jni,
		"Foo.class":                  "\xca\xfe",
	})
	archives, notes := pinArchives(archiveProfile(home), home, t.TempDir(), proc, nil)
	if len(notes) != 0 || archives.count != 1 {
		t.Fatalf("segments = %d, notes = %v: only the library counts", archives.count, notes)
	}
	ps := pins{archives: archives}

	mapped := fakeMappedLibrary(t, proc, jni)
	if got := ps.untrusted(proxy.Identity{PID: fakePID, Code: []jailinit.MappedFile{mapped}}); got != "" {
		t.Errorf("a library from the archive: %q", got)
	}

	other := t.TempDir()
	forged := fakeMappedLibrary(t, other, library("a library the agent built"))
	ps.archives.procRoot = other
	if got := ps.untrusted(proxy.Identity{PID: fakePID, Code: []jailinit.MappedFile{forged}}); !strings.Contains(got, "runs code from /tmp/bazel-jni.x/libunix_jni.so") {
		t.Errorf("a library that no archive ships: %q", got)
	}

	tampered := fakeMappedLibrary(t, other, strings.Replace(jni, "jni", "xyz", 1))
	if ps.archives.trusts(fakePID, tampered) {
		t.Error("the same library with one changed byte")
	}
	if ps.archives.trusts(9999, mapped) {
		t.Error("a process that is gone")
	}
}

func TestMappingsThatDoNotNameAnArchivedSegmentAreNotRead(t *testing.T) {
	proc := t.TempDir()
	archives := newCodeArchives(proc)
	if _, err := archives.addLibrary([]byte(jni)); err != nil {
		t.Fatal(err)
	}
	mapped := fakeMappedLibrary(t, proc, jni)
	for name, code := range map[string]jailinit.MappedFile{
		"another offset": {Range: mapped.Range, Offset: 4096},
		"a longer range": {Range: fmt.Sprintf("%x-%x", mapStart, mapStart+3*os.Getpagesize())},
		"no range":       {},
		"a bad range":    {Range: "../../x-y"},
		"an empty range": {Range: "10-10"},
	} {
		if archives.trusts(fakePID, code) {
			t.Errorf("%s", name)
		}
	}
	if !archives.trusts(fakePID, mapped) {
		t.Error("the matching mapping must pass")
	}
}

func TestArchiveLimitsAndNotes(t *testing.T) {
	home := t.TempDir()
	jar := filepath.Join(home, ".cache", "bazel", "install", "abc", "A-server.jar")
	writeZip(t, jar, map[string]string{"a.so": jni, "huge.so": library(strings.Repeat("a", maxLibraryBytes))})
	archives, notes := pinArchives(archiveProfile(home), home, t.TempDir(), t.TempDir(), []string{filepath.Join(home, ".cache", "bazel")})
	if archives.count != 1 {
		t.Errorf("segments = %d: a library over the limit is left out", archives.count)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "the agent can write") {
		t.Errorf("notes = %v", notes)
	}

	if err := os.WriteFile(jar, []byte("not a zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	archives, notes = pinArchives(archiveProfile(home), home, t.TempDir(), t.TempDir(), nil)
	if archives.count != 0 || len(notes) != 1 || !strings.Contains(notes[0], "is not trusted as a source of native code") {
		t.Errorf("segments = %d, notes = %v", archives.count, notes)
	}
}

func fakeProcess(t *testing.T, proc string, pid int, namespace, status string) {
	t.Helper()
	dir := filepath.Join(proc, strconv.Itoa(pid))
	if err := os.MkdirAll(filepath.Join(dir, "ns"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(namespace, filepath.Join(dir, "ns", "pid")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTheJailsPidNamesAProcessOfThatJailOnly(t *testing.T) {
	proc := t.TempDir()
	fakeProcess(t, proc, 500, "pid:[jail]", "Name:\tinit\nNSpid:\t500\t1\n")
	fakeProcess(t, proc, 777, "pid:[jail]", "Name:\tjava\nNSpid:\t777\t104\n")
	fakeProcess(t, proc, 888, "pid:[other]", "Name:\tjava\nNSpid:\t888\t104\n")
	fakeProcess(t, proc, 999, "pid:[host]", "Name:\tjava\nNSpid:\t104\n")
	if got, err := hostPID(proc, 500, 104); err != nil || got != 777 {
		t.Errorf("hostPID = %d, %v: a process of another namespace has the same pid", got, err)
	}
	if _, err := hostPID(proc, 500, 105); err == nil {
		t.Error("no process has pid 105")
	}
}

func TestArchivedCodeIsReadFromTheHostPidOfTheJailsProcess(t *testing.T) {
	proc := t.TempDir()
	archives := newCodeArchives(proc)
	if _, err := archives.addLibrary([]byte(jni)); err != nil {
		t.Fatal(err)
	}
	mapped := fakeMappedLibrary(t, proc, jni)
	archives.hostPID = func(jailPID int) (int, error) { return fakePID, nil }
	if err := archives.check(104, mapped); err != nil {
		t.Errorf("the jail pid 104 is host pid %d: %v", fakePID, err)
	}
	archives.hostPID = func(int) (int, error) { return 0, errors.New("gone") }
	if err := archives.check(104, mapped); err == nil || !strings.Contains(err.Error(), "gone") {
		t.Errorf("check = %v", err)
	}
}

func TestAWithheldCredentialSaysWhyTheArchivesDidNotTrustTheCode(t *testing.T) {
	proc := t.TempDir()
	archives := newCodeArchives(proc)
	if _, err := archives.addLibrary([]byte(jni)); err != nil {
		t.Fatal(err)
	}
	ps := pins{archives: archives}
	mapped := fakeMappedLibrary(t, proc, library("another"))
	got := ps.untrusted(proxy.Identity{PID: fakePID, Code: []jailinit.MappedFile{mapped}})
	if !strings.Contains(got, "match no archived library") {
		t.Errorf("reason = %q", got)
	}
	if got := (pins{}).untrusted(proxy.Identity{Code: []jailinit.MappedFile{mapped}}); !strings.Contains(got, "pins no archive") {
		t.Errorf("reason = %q", got)
	}
}

func TestPinnedLibrariesAreTrustedAtTheirPathUntilTheyChange(t *testing.T) {
	home := t.TempDir()
	lib := filepath.Join(home, ".cache", "bazel", "install", "abc", "libcpu_profiler.so")
	if err := os.MkdirAll(filepath.Dir(lib), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lib, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &profile.Profile{
		Mounts:        []profile.Mount{{Path: filepath.Join(home, ".cache", "bazel"), Mode: profile.ModeWrite}},
		CodeLibraries: []string{filepath.Join(home, ".cache", "bazel", "install", "*", "libcpu_profiler.so")},
	}
	ps := pins{code: map[string]jailinit.FileID{}}
	notes := ps.pinLibraries(p, home, t.TempDir(), []string{filepath.Join(home, ".cache", "bazel")})
	if len(notes) != 1 || !strings.Contains(notes[0], "the agent can write") {
		t.Errorf("notes = %v", notes)
	}
	info, err := os.Stat(lib)
	if err != nil {
		t.Fatal(err)
	}
	id := proxy.Identity{Exe: "/nix/store/x/bin/java", Code: []jailinit.MappedFile{{Path: lib, File: jailinit.FileIDOf(info)}}}
	if got := ps.untrusted(id); got != "" {
		t.Errorf("the pinned library: %q", got)
	}
	id.Code[0].File.Ctime++
	if got := ps.untrusted(id); got == "" {
		t.Error("a library written after the session started")
	}
}
