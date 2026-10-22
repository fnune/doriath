package bundle

import (
	"os"
	"strings"
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
		if k == "DORIATH_BWRAP" {
			return "/opt/bwrap"
		}
		return ""
	})
	if err != nil || p != "/opt/bwrap" {
		t.Fatalf("got %s, %v", p, err)
	}
}

func TestExtractReplacesATamperedCopy(t *testing.T) {
	dir := t.TempDir()
	want := []byte("#!/bin/sh\necho hi\n")
	p, err := extract(dir, "tool", want)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("#!/bin/sh\nevil\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if again, err := extract(dir, "tool", want); err != nil || again != p {
		t.Fatalf("extract = %s, %v", again, err)
	}
	if got, err := os.ReadFile(p); err != nil || string(got) != string(want) {
		t.Fatalf("content = %q, %v", got, err)
	}
}

func TestWithoutBwrapSaysHowToGetOne(t *testing.T) {
	if Bundled() {
		t.Skip("bundled build")
	}
	t.Setenv("PATH", t.TempDir())
	_, err := Bwrap(t.TempDir(), func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "build with -tags bundled or set DORIATH_BWRAP") {
		t.Fatalf("err = %v", err)
	}
}
