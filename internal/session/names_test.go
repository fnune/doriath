package session

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/fnune/doriath/internal/config"
)

func testPaths(t *testing.T) config.Paths {
	dir := t.TempDir()
	return config.Paths{Runtime: filepath.Join(dir, "run"), State: filepath.Join(dir, "state")}
}

func TestASessionIsNamedAfterAnAnimal(t *testing.T) {
	id, err := newID(testPaths(t))
	if err != nil || !regexp.MustCompile(`^[a-z]+-[a-z]+$`).MatchString(id) {
		t.Fatalf("id = %q, %v", id, err)
	}
}

func TestNoTwoSessionsShareAName(t *testing.T) {
	paths := testPaths(t)
	seen := map[string]bool{}
	for range 200 {
		id, err := newID(paths)
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatalf("%s given twice", id)
		}
		seen[id] = true
	}
}

func TestANameWithAKeptBackupIsNotGivenAgain(t *testing.T) {
	paths := testPaths(t)
	if err := os.MkdirAll(paths.Backups(), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, a := range adjectives {
		for _, n := range animals {
			if a+"-"+n != "quiet-otter" {
				if err := os.WriteFile(recordPath(paths, a+"-"+n), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	for range 3 {
		if id, err := newID(paths); err == nil && id != "quiet-otter" {
			t.Fatalf("id = %q", id)
		}
	}
}
