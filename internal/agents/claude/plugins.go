package claude

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

func copyPluginsIn(real, private string) error {
	parent := filepath.Dir(private)
	staging, err := os.MkdirTemp(parent, ".plugins-new-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	if err := copyTree(real, staging); err != nil {
		return err
	}
	trash, err := os.MkdirTemp(parent, ".plugins-old-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(trash) }()
	if err := os.Rename(private, filepath.Join(trash, "plugins")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return os.Rename(staging, private)
}

func copyTree(real, dest string) error {
	err := filepath.WalkDir(real, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(real, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o700)
		case d.Type().IsRegular():
			info, err := d.Info()
			if err != nil {
				return err
			}
			return copyFile(path, target, info.Mode().Perm())
		}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func copyFile(src, dest string, perm fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
