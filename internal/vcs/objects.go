package vcs

import (
	"compress/zlib"
	"context"
	"crypto/sha1" //nolint:gosec // git names objects by SHA-1
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func dropForgedObjects(ctx context.Context, t Tools, gitDir, mirror string) []string {
	newHash := sha1.New
	if format, err := runStore(ctx, t, gitDir, "rev-parse", "--show-object-format"); err == nil && strings.TrimSpace(format) == "sha256" {
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
		if _, err := runStore(ctx, t, gitDir, "verify-pack", base+".idx"); err == nil {
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

const zlibMaxRatio = 1032

func looseObjectID(p string, newHash func() hash.Hash) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	z, err := zlib.NewReader(f)
	if err != nil {
		return "", err
	}
	header, err := readHeader(z)
	if err != nil {
		return "", err
	}
	_, size, _ := strings.Cut(strings.TrimSuffix(header, "\x00"), " ")
	n, err := strconv.ParseInt(size, 10, 64)
	if err != nil || n < 0 || n > zlibMaxRatio*info.Size() {
		return "", errors.New("impossible object size")
	}
	h := newHash()
	h.Write([]byte(header))
	if copied, err := io.Copy(h, io.LimitReader(z, n)); err != nil || copied != n {
		return "", errors.New("object shorter than its header says")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readHeader(r io.Reader) (string, error) {
	var header []byte
	b := make([]byte, 1)
	for len(header) < 64 {
		if _, err := io.ReadFull(r, b); err != nil {
			return "", errors.New("no object header")
		}
		header = append(header, b[0])
		if b[0] == 0 {
			return string(header), nil
		}
	}
	return "", errors.New("no object header")
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}
