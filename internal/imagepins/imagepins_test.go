package imagepins

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func digest(c string) string { return "sha256:" + strings.Repeat(c, 64) }

func TestPinAndLookUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "images", "dev.json")
	f := NewFile(path)
	if _, ok, err := f.Pinned("docker.io/library/postgres:16"); ok || err != nil {
		t.Fatalf("pinned before any pull: %v, %v", ok, err)
	}
	if err := f.Pin("docker.io/library/postgres:16", digest("a")); err != nil {
		t.Fatal(err)
	}
	if err := f.Pin("docker.io/library/postgres:16", digest("b")); err != nil {
		t.Fatal(err)
	}
	other := NewFile(path)
	if d, ok, err := other.Pinned("docker.io/library/postgres:16"); !ok || err != nil || d != digest("b") {
		t.Fatalf("got %q, %v, %v", d, ok, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v, %v", info, err)
	}
}

func TestConcurrentPinsKeepEachOther(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dev.json")
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := NewFile(path).Pin(fmt.Sprintf("docker.io/library/app:%d", i), digest("a")); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for i := range 20 {
		if _, ok, err := NewFile(path).Pinned(fmt.Sprintf("docker.io/library/app:%d", i)); !ok || err != nil {
			t.Errorf("pin %d lost: %v", i, err)
		}
	}
}

func TestRejects(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"bad digest":    `{"pins":{"docker.io/library/a:1":"latest"}}`,
		"unknown field": `{"pins":{},"extra":1}`,
		"not json":      `pins`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := NewFile(path).Pinned("docker.io/library/a:1"); err == nil {
				t.Fatal("read a bad pin file")
			}
			if err := NewFile(path).Pin("docker.io/library/b:1", digest("b")); err == nil {
				t.Fatal("pinned into a bad pin file")
			}
			if got, _ := os.ReadFile(path); string(got) != content {
				t.Fatalf("a bad pin file was rewritten: %q", got)
			}
		})
	}
	if err := NewFile(filepath.Join(dir, "x.json")).Pin("docker.io/library/a:1", "sha256:short"); err == nil {
		t.Fatal("pinned a bad digest")
	}
}
