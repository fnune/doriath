package bundle

import (
	"os"
	"testing"
)

func TestExtractIsIdempotentAndPrivate(t *testing.T) {
	dir := t.TempDir()
	p1, err := extract(dir, "tool", []byte("#!/bin/sh\necho hi\n"))
	if err != nil {
		t.Fatal(err)
	}
	p2, err := extract(dir, "tool", []byte("#!/bin/sh\necho hi\n"))
	if err != nil || p1 != p2 {
		t.Fatalf("second extract: %s, %v", p2, err)
	}
	info, err := os.Stat(p1)
	if err != nil || info.Mode().Perm() != 0o500 {
		t.Fatalf("mode = %v, %v", info.Mode(), err)
	}
	p3, err := extract(dir, "tool", []byte("other"))
	if err != nil || p3 == p1 {
		t.Fatalf("different content must get a different path: %s", p3)
	}
}

func TestFallback(t *testing.T) {
	if Bundled() {
		t.Skip("bundled build")
	}
	p, err := Bwrap(t.TempDir(), func(k string) string {
		if k == "GIRDLE_BWRAP" {
			return "/opt/bwrap"
		}
		return ""
	})
	if err != nil || p != "/opt/bwrap" {
		t.Fatalf("got %s, %v", p, err)
	}
}
