package vcs

import (
	"bytes"
	"compress/zlib"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFinishDropsObjectsTheAgentForged(t *testing.T) {
	r := repo(t)
	ctx, tools := context.Background(), Tools{Git: "git"}
	backup := filepath.Join(t.TempDir(), "b")
	rec := &Record{Session: "s1", Started: time.Now()}
	if err := Start(ctx, tools, backup, rec, []string{r}); err != nil {
		t.Fatal(err)
	}
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

	var out strings.Builder
	if err := Finish(ctx, tools, backup, rec, &out); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{forgedLoose, badPack + ".pack", badPack + ".idx", graph} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s stays:\n%s", p, out.String())
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
