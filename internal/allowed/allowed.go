// Package allowed keeps the grants of each profile you allowed, in a JSON
// file outside the jail, so that doriath asks again when a profile grants
// more.
package allowed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// Key names one allowed profile: a profile spec in one repository, or
// outside any repository when Repository is empty. A repository module
// differs between repositories, so the same spec asks in each one.
type Key struct {
	Profile    string `json:"profile"`
	Repository string `json:"repository,omitempty"`
}

type Store struct {
	dir string
}

func NewStore(dir string) Store { return Store{dir: dir} }

type document struct {
	Key
	Grants []string `json:"grants"`
}

// Grants returns what you last allowed for key, and false when you never
// allowed it.
func (s Store) Grants(key Key) ([]string, bool, error) {
	data, err := os.ReadFile(s.path(key))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read the allowed grants of profile %s: %w", key.Profile, err)
	}
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, false, fmt.Errorf("read the allowed grants of profile %s: %w", key.Profile, err)
	}
	if doc.Key != key {
		return nil, false, nil
	}
	slices.Sort(doc.Grants)
	return doc.Grants, true, nil
}

func (s Store) Allow(key Key, grants []string) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(document{Key: key, Grants: grants}, "", "  ")
	if err != nil {
		return err
	}
	path := s.path(key)
	tmp, err := os.CreateTemp(s.dir, filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (s Store) path(key Key) string {
	sum := sha256.Sum256([]byte(key.Profile + "\x00" + key.Repository))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:8])+".json")
}
