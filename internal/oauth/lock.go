package oauth

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// lock takes an exclusive lock that every process takes before it refreshes
// this login. It returns a function that releases it.
func (t *Tokens) lock(profile, name string) (func(), error) {
	if t.lockDir == "" {
		return func() {}, nil
	}
	if err := os.MkdirAll(t.lockDir, 0o700); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(profile + "/" + name))
	f, err := os.OpenFile(filepath.Join(t.lockDir, "login-"+hex.EncodeToString(sum[:8])+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}
