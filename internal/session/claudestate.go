package session

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// copyProjectIn gives the jail this project's Claude files, transcripts and
// memory, as copies it can change without changing the originals. Only
// regular files are copied, so a link in the real directory cannot pull other
// files into the profile.
func copyProjectIn(real, private string) error {
	if err := os.MkdirAll(private, 0o700); err != nil {
		return err
	}
	err := filepath.WalkDir(real, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(real, path)
		if err != nil {
			return err
		}
		dest := filepath.Join(private, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(dest, 0o700)
		case d.Type().IsRegular():
			return copyIfNewer(path, dest)
		}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// copyTranscriptsBack returns the session's transcripts to the real project
// directory, so the desktop can resume them. Memory and other files the agent
// wrote stay in the profile, because desktop sessions read them as
// instructions.
func copyTranscriptsBack(private, real string) error {
	entries, err := os.ReadDir(private)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(real, 0o700); err != nil {
		return err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		if err := copyIfNewer(filepath.Join(private, e.Name()), filepath.Join(real, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// copyIfNewer replaces dest with src when src changed later, through a
// temporary file so a reader never sees half a transcript. A link at dest is
// replaced rather than followed.
func copyIfNewer(src, dest string) error {
	from, err := os.Stat(src)
	if err != nil {
		return err
	}
	if to, err := os.Lstat(dest); err == nil && to.Mode().IsRegular() && !from.ModTime().After(to.ModTime()) {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".girdle-*")
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
