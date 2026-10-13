// Package bundle carries the static helpers girdle needs, so that it does not
// depend on what the system has installed. A release build embeds them. A
// development build without the "bundled" tag falls back to the system.
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Bwrap returns the path of a bubblewrap binary. The embedded copy is written
// once to dir, named by its hash, and reused after that.
func Bwrap(dir string, getenv func(string) string) (string, error) {
	if len(bwrap) > 0 {
		return extract(dir, "bwrap", bwrap)
	}
	if p := getenv("GIRDLE_BWRAP"); p != "" {
		return p, nil
	}
	p, err := exec.LookPath("bwrap")
	if err != nil {
		return "", errors.New("this girdle build has no bundled bubblewrap and none is on PATH: build with -tags bundled or set GIRDLE_BWRAP")
	}
	return p, nil
}

func Bundled() bool { return len(bwrap) > 0 }

func extract(dir, name string, data []byte) (string, error) {
	sum := sha256.Sum256(data)
	target := filepath.Join(dir, hex.EncodeToString(sum[:12]), name)
	if existing, err := os.ReadFile(target); err == nil && sha256.Sum256(existing) == sum {
		return target, nil
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", filepath.Dir(target), err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), name+".*")
	if err != nil {
		return "", fmt.Errorf("extract %s: %w", name, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("extract %s: %w", name, err)
	}
	if err := tmp.Chmod(0o500); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("extract %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("extract %s: %w", name, err)
	}
	if err := os.Rename(tmp.Name(), target); err != nil {
		return "", fmt.Errorf("extract %s: %w", name, err)
	}
	return target, nil
}
