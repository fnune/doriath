package vcs

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // git names objects by SHA-1
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func packedRepo(t *testing.T) string {
	t.Helper()
	r := repo(t)
	for i := range 20 {
		if err := os.WriteFile(filepath.Join(r, "f"), fmt.Appendf(nil, "%d", i), 0o644); err != nil {
			t.Fatal(err)
		}
		git(t, r, "add", "f")
		git(t, r, "commit", "-q", "-m", fmt.Sprint(i))
	}
	git(t, r, "repack", "-q", "-a", "-d")
	return r
}

func packs(t *testing.T, r string) []string {
	t.Helper()
	out, _ := filepath.Glob(filepath.Join(r, ".git", "objects", "pack", "*.pack"))
	return out
}

func TestFinishRemovesTheWholeHistoryPackThatAGCInTheJailWrote(t *testing.T) {
	r := packedRepo(t)
	before := packs(t, r)
	rec := &Record{Session: "s1", Started: time.Now()}
	f := start(t, rec, r)

	if err := os.WriteFile(filepath.Join(r, "f"), []byte("the agent's"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, r, "commit", "-q", "-am", "the agent's work")
	work := git(t, r, "rev-parse", "HEAD")
	git(t, r, "repack", "-q", "-a")
	if len(packs(t, r)) != len(before)+1 {
		t.Fatalf("the repack wrote no pack: %v", packs(t, r))
	}

	if out := f.finish(); strings.Contains(out, "removed") {
		t.Errorf("a pack of genuine objects is no forgery:\n%s", out)
	}
	if got := packs(t, r); !slices.Equal(got, before) {
		t.Errorf("packs = %v, want only the packs from the start %v", got, before)
	}
	if git(t, r, "cat-file", "-t", work) != "commit" {
		t.Error("the agent's commit must stay readable")
	}
	git(t, r, "fsck", "--no-dangling")
}

func TestFinishVerifiesAPackOfNewObjectsAndReportsItsProgress(t *testing.T) {
	r := packedRepo(t)
	rec := &Record{Session: "s1", Started: time.Now()}
	f := start(t, rec, r)

	for i := range 5 {
		if err := os.WriteFile(filepath.Join(r, "f"), fmt.Appendf(nil, "new %d", i), 0o644); err != nil {
			t.Fatal(err)
		}
		git(t, r, "commit", "-q", "-am", fmt.Sprint(i))
	}
	git(t, r, "repack", "-q")
	newPacks := len(packs(t, r))

	var seen []PackCheck
	if err := Finish(f.ctx, f.tools, f.backup, f.rec, &strings.Builder{}, &strings.Builder{}, func(c PackCheck) { seen = append(seen, c) }); err != nil {
		t.Fatal(err)
	}
	if len(packs(t, r)) != newPacks {
		t.Errorf("a pack of verified new objects must stay: %v", packs(t, r))
	}
	if len(seen) < 2 {
		t.Fatalf("progress = %v", seen)
	}
	first, last := seen[0], seen[len(seen)-1]
	if first.Repo != r || first.Pack != 1 || first.Packs != 1 || first.Bytes == 0 || first.Done != 0 {
		t.Errorf("first progress = %+v", first)
	}
	if last.Done != 1 {
		t.Errorf("last progress = %+v, want all done", last)
	}
}

func TestCopyVerifiedObjectsRefusesAnObjectWhoseContentHasAnotherName(t *testing.T) {
	dir := t.TempDir()
	id := strings.Repeat("1", 40)
	fake := filepath.Join(dir, "git")
	script := fmt.Sprintf("#!/bin/sh\ncat >/dev/null\nprintf '%s blob 5\\nagent\\n'\n", id)
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	gitDir := filepath.Join(dir, "store")
	pack := filepath.Join(gitDir, "objects", "pack", "pack-1.pack")
	if err := os.MkdirAll(filepath.Dir(pack), 0o755); err != nil {
		t.Fatal(err)
	}

	err := copyVerifiedObjects(context.Background(), Tools{Git: fake}, gitDir, pack, []string{id}, sha1.New)
	if err == nil || !strings.Contains(err.Error(), "its content has the name") {
		t.Fatalf("err = %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(gitDir, "objects", "11", "*")); len(left) != 0 {
		t.Errorf("the forged object stays: %v", left)
	}
}

func TestReadProgressWeighsTheDeltaPhase(t *testing.T) {
	var seen []float64
	readProgress(strings.NewReader("Indexing objects:  50% (5/10)\rIndexing objects: 100% (10/10), done.\nResolving deltas:  50% (2/4)\rnoise\n"), func(d float64) { seen = append(seen, d) })
	want := []float64{0.015, 0.03, 0.03 + 0.97/2}
	if len(seen) != len(want) {
		t.Fatalf("seen = %v", seen)
	}
	for i := range want {
		if d := seen[i] - want[i]; d > 1e-9 || d < -1e-9 {
			t.Errorf("seen = %v, want %v", seen, want)
		}
	}
}

func TestPackNamesRefusesAnIndexThatClaimsMoreThanItHolds(t *testing.T) {
	idx := filepath.Join(t.TempDir(), "pack-1.idx")
	data := append(slices.Clone(idxMagic), make([]byte, 256*4)...)
	data[len(data)-1] = 200
	if err := os.WriteFile(idx, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := packNames(idx, sha1.Size); err == nil {
		t.Error("an index shorter than its count must fail")
	}
}

func TestVerifyPackRefusesAnIndexThatDoesNotMatchItsPack(t *testing.T) {
	r := packedRepo(t)
	pack := packs(t, r)[0]
	idx := strings.TrimSuffix(pack, ".pack") + ".idx"
	data, err := os.ReadFile(idx)
	if err != nil {
		t.Fatal(err)
	}
	data[idxHeader+3] ^= 0xff
	if err := os.Chmod(idx, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idx, data, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := verifyPack(context.Background(), Tools{Git: "git"}, filepath.Join(r, ".git"), pack, func(float64) {}); err == nil {
		t.Error("an index that names other objects must fail")
	}
}

func TestABadMirrorIndexCanOnlyMakeMoreObjectsNew(t *testing.T) {
	mirror := t.TempDir()
	name := func(b byte) []byte { return bytes.Repeat([]byte{b}, sha1.Size) }
	unsorted := append(slices.Clone(idxMagic), make([]byte, 256*4)...)
	unsorted[len(unsorted)-1] = 2
	unsorted = append(append(unsorted, name(0xcc)...), name(0xaa)...)
	if err := os.MkdirAll(filepath.Join(mirror, "pack"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mirror, "pack", "pack-1.idx"), unsorted, 0o444); err != nil {
		t.Fatal(err)
	}
	got := notInMirror([][]byte{name(0xaa), name(0xbb), name(0xcc), name(0xdd)}, mirror, sha1.Size)
	want := []string{hex.EncodeToString(name(0xaa)), hex.EncodeToString(name(0xbb)), hex.EncodeToString(name(0xdd))}
	if !slices.Equal(got, want) {
		t.Errorf("new = %v, want %v", got, want)
	}
}
