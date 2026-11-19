package claude

import (
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func copyProjectIn(real, anchor, rel string) error {
	root, err := os.OpenRoot(anchor)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := root.MkdirAll(rel, 0o700); err != nil {
		return err
	}
	err = filepath.WalkDir(real, func(src string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		sub, err := filepath.Rel(real, src)
		if err != nil {
			return err
		}
		dest := filepath.Join(rel, sub)
		switch {
		case d.IsDir():
			return root.MkdirAll(dest, 0o700)
		case d.Type().IsRegular():
			return copyIn(src, root, dest)
		}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func copyTranscriptsBack(anchor, rel, real string) error {
	root, err := os.OpenRoot(anchor)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer func() { _ = root.Close() }()
	private, err := root.OpenRoot(rel)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer func() { _ = private.Close() }()
	entries, err := fs.ReadDir(private.FS(), ".")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(real, 0o700); err != nil {
		return err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		if err := copyOut(private, e.Name(), filepath.Join(real, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func newerThan(from fs.FileInfo, to fs.FileInfo, err error) bool {
	return err != nil || !to.Mode().IsRegular() || from.ModTime().After(to.ModTime())
}

func copyIn(src string, root *os.Root, dest string) error {
	from, err := os.Stat(src)
	if err != nil {
		return err
	}
	to, err := root.Lstat(dest)
	if !newerThan(from, to, err) {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmpName := path.Join(filepath.Dir(dest), ".doriath-"+rand.Text())
	tmp, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(tmpName) }()
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := root.Chtimes(tmpName, from.ModTime(), from.ModTime()); err != nil {
		return err
	}
	return root.Rename(tmpName, dest)
}

func copyOut(root *os.Root, name, dest string) error {
	in, err := root.Open(name)
	if err != nil {
		return err
	}
	defer in.Close()
	from, err := in.Stat()
	if err != nil {
		return err
	}
	to, err := os.Lstat(dest)
	if !newerThan(from, to, err) {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".doriath-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chtimes(tmp.Name(), from.ModTime(), from.ModTime()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dest)
}
