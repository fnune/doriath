package vcs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveTreeRemovesEveryLooseObject(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "backup")
	for i := range 100 {
		p := filepath.Join(dir, "objects", string(rune('a'+i%26))+"x", string(rune('a'+i/26)))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o444); err != nil {
			t.Fatal(err)
		}
	}
	if err := removeTree(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("backup is still there: %v", err)
	}
}

func TestAFailedFileStopsTheWalk(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	failure := errors.New("copy failed")
	err := walkParallel(dir, func(p string, d fs.DirEntry, err error) (func() error, error) {
		if d.IsDir() {
			return nil, nil
		}
		return func() error { return failure }, nil
	})
	if !errors.Is(err, failure) {
		t.Fatalf("err = %v, want %v", err, failure)
	}
}

func TestTheBackupHoldsEveryLooseObjectInEveryFanoutDirectory(t *testing.T) {
	src, dst := filepath.Join(t.TempDir(), "objects"), filepath.Join(t.TempDir(), "backup")
	var want []string
	for i := range 256 {
		rel := filepath.Join(fmt.Sprintf("%02x", i), "object")
		if err := os.MkdirAll(filepath.Join(src, filepath.Dir(rel)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, rel), []byte(rel), 0o444); err != nil {
			t.Fatal(err)
		}
		want = append(want, rel)
	}
	if err := mirror(src, dst); err != nil {
		t.Fatal(err)
	}
	for _, rel := range want {
		if data, err := os.ReadFile(filepath.Join(dst, rel)); err != nil || string(data) != rel {
			t.Fatalf("%s in the backup: %q, %v", rel, data, err)
		}
	}
}
