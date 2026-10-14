package vcs

import (
	"compress/zlib"
	"context"
	"crypto/sha1" //nolint:gosec // git names objects by SHA-1
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// dropForgedObjects removes what the session added to a store and git
// cannot vouch for: a loose object whose content does not hash to its name,
// or a pack that git verify-pack refuses. A forged object would stand in
// for the real one, for example one your next fetch then skips as present.
// It also removes new indexes git rebuilds on its own, such as bitmaps and
// commit graphs, which could otherwise lie about the objects. Files that
// were there at the start are in mirror, and Finish restores those.
func dropForgedObjects(ctx context.Context, t Tools, gitDir, mirror string) []string {
	newHash := sha1.New
	if format, err := run(ctx, t.Git, "--git-dir", gitDir, "rev-parse", "--show-object-format"); err == nil && strings.TrimSpace(format) == "sha256" {
		newHash = sha256.New
	}
	objects := filepath.Join(gitDir, "objects")
	var dropped, packs []string
	drop := func(p string) {
		if os.Remove(p) == nil {
			rel, _ := filepath.Rel(gitDir, p)
			dropped = append(dropped, rel)
		}
	}
	_ = filepath.WalkDir(objects, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(objects, p)
		if _, err := os.Lstat(filepath.Join(mirror, rel)); err == nil {
			return nil
		}
		dir, name := filepath.Dir(rel), d.Name()
		switch {
		case !d.Type().IsRegular():
			drop(p)
		case len(dir) == 2 && isHex(dir):
			if id, err := looseObjectID(p, newHash); err != nil || id != dir+name {
				drop(p)
			}
		case dir == "pack" && strings.HasSuffix(name, ".pack"):
			packs = append(packs, p)
		case dir == "pack" && rebuiltIndex(name), strings.HasPrefix(rel, filepath.Join("info", "commit-graph")):
			drop(p)
		}
		return nil
	})
	for _, pack := range packs {
		base := strings.TrimSuffix(pack, ".pack")
		if _, err := run(ctx, t.Git, "--git-dir", gitDir, "verify-pack", base+".idx"); err == nil {
			continue
		}
		matches, _ := filepath.Glob(base + ".*")
		for _, m := range matches {
			drop(m)
		}
	}
	return dropped
}

func rebuiltIndex(name string) bool {
	for _, ext := range []string{".rev", ".bitmap", ".mtimes"} {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return strings.HasPrefix(name, "multi-pack-index")
}

func looseObjectID(p string, newHash func() hash.Hash) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	z, err := zlib.NewReader(f)
	if err != nil {
		return "", err
	}
	h := newHash()
	if _, err := io.Copy(h, z); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}
