package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLargeScratchFoldersAreReportedPerToolWithTheCachesThatKeepThem(t *testing.T) {
	root := t.TempDir()
	write := func(rel string, size int64) {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(size); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	write(".cache/bazel-disk/cas/ab/blob", largeScratch)
	write(".cache/bazel-disk/cas/cd/blob", 2)
	write(".m2/repository/x.jar", largeScratch+1)
	write(".cache/small/file", 10)
	write(".cache/loose.log", largeScratch)

	got := largeScratchFolders(root)
	if len(got) != 3 || got[0].path != "~/.cache/bazel-disk" || got[1].path != "~/.m2" || got[2].path != "~/.cache/loose.log" {
		t.Fatalf("folders = %+v", got)
	}
	note := scratchNote(got, "work")
	if !strings.Contains(note, "add to profile work:\n[[caches]]\npath = \"~/.cache/bazel-disk\"\n\n[[caches]]\npath = \"~/.m2\"") || strings.Contains(note, "path = \"~/.cache/loose.log\"") {
		t.Errorf("note = %s", note)
	}
}
