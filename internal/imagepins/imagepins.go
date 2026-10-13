// Package imagepins keeps the digest each container image tag resolved to the
// first time a profile pulled it, in a JSON file outside the jail.
package imagepins

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// File is one profile's pins. Every lookup reads the file, so that a pin
// recorded by another session of the profile counts at once.
type File struct {
	path string
}

func NewFile(path string) *File { return &File{path: path} }

type document struct {
	Pins map[string]string `json:"pins"`
}

func (f *File) Pinned(ref string) (string, bool, error) {
	doc, err := f.read()
	if err != nil {
		return "", false, err
	}
	d, ok := doc.Pins[ref]
	return d, ok, nil
}

// Pin holds a lock across the read and the write, so that sessions pinning
// different tags at once keep each other's pins.
func (f *File) Pin(ref, digest string) error {
	if !digestPattern.MatchString(digest) {
		return fmt.Errorf("pin %s: %q is not a sha256 digest", ref, digest)
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(f.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock %s: %w", f.path, err)
	}
	doc, err := f.read()
	if err != nil {
		return err
	}
	doc.Pins[ref] = digest
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.path), filepath.Base(f.path)+".*")
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
	return os.Rename(tmp.Name(), f.path)
}

func (f *File) read() (document, error) {
	doc := document{Pins: map[string]string{}}
	data, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return doc, nil
	}
	if err != nil {
		return document{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return document{}, fmt.Errorf("%s: %w", f.path, err)
	}
	if doc.Pins == nil {
		doc.Pins = map[string]string{}
	}
	for ref, d := range doc.Pins {
		if !digestPattern.MatchString(d) {
			return document{}, fmt.Errorf("%s: pin of %s: %q is not a sha256 digest", f.path, ref, d)
		}
	}
	return doc, nil
}
