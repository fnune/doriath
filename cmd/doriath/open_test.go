package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAPathOpensAsAFileLinkFromTheFolderOfTheAgent(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("plan.md", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for arg, want := range map[string]string{
		"plan.md":                     "file://" + filepath.Join(dir, "plan.md"),
		"https://example.com/plan.md": "https://example.com/plan.md",
		"missing.md":                  "missing.md",
	} {
		if got, err := linkOrFile(arg); err != nil || got != want {
			t.Errorf("%s: %q, %v, want %q", arg, got, err, want)
		}
	}
}
