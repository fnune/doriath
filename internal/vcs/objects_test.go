package vcs

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1" //nolint:gosec // git names objects by SHA-1
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFinishDropsObjectsTheAgentForged(t *testing.T) {
	r := repo(t)
	rec := &Record{Session: "s1", Started: time.Now()}
	f := start(t, rec, r)
	objects := filepath.Join(r, ".git", "objects")

	git(t, r, "commit", "-q", "--allow-empty", "-m", "the agent's work")
	genuine := git(t, r, "rev-parse", "HEAD")
	upstream := "1111111111111111111111111111111111111111"
	forgedLoose := filepath.Join(objects, upstream[:2], upstream[2:])
	writeLoose(t, forgedLoose, "blob 5\x00agent")

	git(t, r, "repack", "-q", "-d")
	packs, _ := filepath.Glob(filepath.Join(objects, "pack", "*.pack"))
	if len(packs) != 1 {
		t.Fatalf("packs: %v", packs)
	}
	goodPack := packs[0]
	badPack := filepath.Join(objects, "pack", "pack-"+strings.Repeat("2", 40))
	data, err := os.ReadFile(goodPack)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 0xff
	if err := os.WriteFile(badPack+".pack", data, 0o444); err != nil {
		t.Fatal(err)
	}
	idx, err := os.ReadFile(strings.TrimSuffix(goodPack, ".pack") + ".idx")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badPack+".idx", idx, 0o444); err != nil {
		t.Fatal(err)
	}
	graph := filepath.Join(objects, "info", "commit-graph")
	if err := os.WriteFile(graph, []byte("lies"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := f.finish()
	for _, p := range []string{forgedLoose, badPack + ".pack", badPack + ".idx", graph} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s stays:\n%s", p, out)
		}
	}
	if _, err := os.Stat(goodPack); err != nil {
		t.Errorf("the agent's genuine pack must stay: %v", err)
	}
	if git(t, r, "cat-file", "-t", genuine) != "commit" {
		t.Error("the agent's genuine commit must stay readable")
	}
}

func writeLoose(t *testing.T, p, content string) {
	t.Helper()
	var buf bytes.Buffer
	z := zlib.NewWriter(&buf)
	if _, err := io.WriteString(z, content); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, buf.Bytes(), 0o444); err != nil {
		t.Fatal(err)
	}
}

func TestLooseObjectIDStopsAtTheDeclaredSize(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	writeLoose(t, real, "blob 5\x00hello")
	if id, err := looseObjectID(real, sha1.New); err != nil || id != "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0" {
		t.Fatalf("id = %q, %v", id, err)
	}
	bomb := filepath.Join(dir, "bomb")
	writeLoose(t, bomb, "blob 999999999999\x00"+strings.Repeat("\x00", 1<<20))
	if _, err := looseObjectID(bomb, sha1.New); err == nil {
		t.Fatal("an object claiming more than zlib can expand to must fail")
	}
}

func TestLooseObjectIDRejectsMalformedObjects(t *testing.T) {
	for name, content := range map[string]string{
		"no header end":                 "blob 5 " + strings.Repeat("x", 100),
		"a size that is not a number":   "blob five\x00hello",
		"a negative size":               "blob -1\x00hello",
		"content shorter than its size": "blob 9\x00hello",
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "object")
			writeLoose(t, p, content)
			if id, err := looseObjectID(p, sha1.New); err == nil {
				t.Fatalf("id = %q", id)
			}
		})
	}
	t.Run("not zlib", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "object")
		if err := os.WriteFile(p, []byte("blob 5\x00hello"), 0o444); err != nil {
			t.Fatal(err)
		}
		if id, err := looseObjectID(p, sha1.New); err == nil {
			t.Fatalf("id = %q", id)
		}
	})
}

func TestFinishCoversSubmoduleStores(t *testing.T) {
	lib := repo(t)
	r := repo(t)
	git(t, r, "-c", "protocol.file.allow=always", "submodule", "add", "-q", lib, "lib")
	git(t, r, "-c", "protocol.file.allow=always", "submodule", "add", "-q", lib, "libs/nested")
	git(t, r, "commit", "-q", "-m", "add lib")
	store := filepath.Join(r, ".git", "modules", "lib")
	nested := filepath.Join(r, ".git", "modules", "libs", "nested")
	rec := &Record{Session: "s1", Started: time.Now()}
	f := start(t, rec, r)
	if len(rec.Repos) != 3 || rec.Repos[1].GitDir != store || rec.Repos[1].Path != filepath.Join(r, "lib") || rec.Repos[2].GitDir != nested {
		t.Fatalf("repos: %+v", rec.Repos)
	}
	forgedNested := filepath.Join(nested, "objects", "11", strings.Repeat("1", 38))
	writeLoose(t, forgedNested, "blob 5\x00agent")
	forged := filepath.Join(store, "objects", "11", strings.Repeat("1", 38))
	writeLoose(t, forged, "blob 5\x00agent")
	git(t, filepath.Join(r, "lib"), "commit", "-q", "--allow-empty", "-m", "agent")

	out := f.finish()
	for _, p := range []string{forged, forgedNested} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("a forged object in a submodule store stays: %s\n%s", p, out)
		}
	}
	if len(rec.Repos[1].Moved) != 1 {
		t.Errorf("the submodule's moved branch is not kept: %+v\n%s", rec.Repos[1], out)
	}
}
