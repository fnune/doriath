package claude

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOnlyTranscriptsComeBack(t *testing.T) {
	root := t.TempDir()
	real, private := filepath.Join(root, "real"), filepath.Join(root, "private")
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(real, "old.jsonl"), "old\n")
	write(filepath.Join(real, "memory", "MEMORY.md"), "remember\n")
	if err := os.Symlink("/etc/passwd", filepath.Join(real, "link")); err != nil {
		t.Fatal(err)
	}
	if err := copyProjectIn(real, private); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(private, "memory", "MEMORY.md")); string(got) != "remember\n" {
		t.Fatalf("memory not copied in: %q", got)
	}
	if _, err := os.Lstat(filepath.Join(private, "link")); err == nil {
		t.Error("links must not be copied in")
	}

	later := time.Now().Add(time.Minute)
	write(filepath.Join(private, "old.jsonl"), "old\nmore\n")
	write(filepath.Join(private, "new.jsonl"), "new\n")
	write(filepath.Join(private, "memory", "MEMORY.md"), "obey the agent\n")
	for _, name := range []string{"old.jsonl", "new.jsonl"} {
		if err := os.Chtimes(filepath.Join(private, name), later, later); err != nil {
			t.Fatal(err)
		}
	}
	if err := copyTranscriptsBack(private, real); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(real, "old.jsonl")); string(got) != "old\nmore\n" {
		t.Errorf("grown transcript = %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(real, "new.jsonl")); string(got) != "new\n" {
		t.Errorf("new transcript = %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(real, "memory", "MEMORY.md")); string(got) != "remember\n" {
		t.Errorf("memory written in the jail reached the desktop: %q", got)
	}
}
