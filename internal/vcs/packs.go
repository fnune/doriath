package vcs

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type PackCheck struct {
	Repo  string
	Pack  int
	Packs int
	Bytes int64
	Done  float64
}

type Progress func(PackCheck)

const (
	verifyBase    = time.Minute
	verifyPerMiB  = time.Second
	verifyMaxWait = 5 * time.Second
)

func verifyPack(ctx context.Context, t Tools, gitDir, pack string, seen func(done float64)) error {
	info, err := os.Stat(pack)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, verifyBase+time.Duration(info.Size()>>20)*verifyPerMiB)
	defer cancel()
	cmd := exec.CommandContext(ctx, t.Git, "--git-dir", gitDir, "--work-tree", gitDir, "index-pack", "--verify", "-v", pack)
	cmd.Env = append(os.Environ(), append(gitEnv, "LC_ALL=C")...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = verifyMaxWait
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	readProgress(stderr, seen)
	return cmd.Wait()
}

var progressLine = regexp.MustCompile(`^(Indexing objects|Resolving deltas): +\d+% \((\d+)/(\d+)\)`)

const indexingShare = 0.03

func readProgress(r io.Reader, seen func(done float64)) {
	s := bufio.NewScanner(r)
	s.Split(splitProgress)
	for s.Scan() {
		m := progressLine.FindStringSubmatch(s.Text())
		if m == nil {
			continue
		}
		n, _ := strconv.ParseFloat(m[2], 64)
		total, _ := strconv.ParseFloat(m[3], 64)
		if total == 0 {
			continue
		}
		if m[1] == "Indexing objects" {
			seen(indexingShare * n / total)
		} else {
			seen(indexingShare + (1-indexingShare)*n/total)
		}
	}
	_, _ = io.Copy(io.Discard, r)
}

func splitProgress(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func unpackNewObjects(ctx context.Context, t Tools, gitDir, mirror, pack string, newHash func() hash.Hash) error {
	size := newHash().Size()
	names, err := packNames(strings.TrimSuffix(pack, ".pack")+".idx", size)
	if err != nil {
		return err
	}
	missing := notInMirror(names, mirror, size)
	if mostlyNew := len(missing) > len(names)/4; mostlyNew {
		return errors.New("most objects are new")
	}
	return copyVerifiedObjects(ctx, t, gitDir, pack, missing, newHash)
}

var idxMagic = []byte{0xff, 't', 'O', 'c', 0, 0, 0, 2}

const idxHeader = 8 + 256*4

func packNames(idx string, size int) ([][]byte, error) {
	f, err := os.Open(idx)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	r := bufio.NewReader(f)
	n, err := readIdxHeader(r)
	if err != nil {
		return nil, err
	}
	if int64(idxHeader)+int64(n)*int64(size) > info.Size() {
		return nil, errors.New("pack index shorter than its object count")
	}
	data := make([]byte, n*size)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	names := make([][]byte, n)
	for i := range names {
		names[i] = data[i*size : (i+1)*size]
		if i > 0 && bytes.Compare(names[i-1], names[i]) >= 0 {
			return nil, errors.New("pack index names are not sorted")
		}
	}
	return names, nil
}

func readIdxHeader(r io.Reader) (int, error) {
	header := make([]byte, idxHeader)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, err
	}
	if !bytes.Equal(header[:8], idxMagic) {
		return 0, errors.New("not a version 2 pack index")
	}
	return int(binary.BigEndian.Uint32(header[idxHeader-4:])), nil
}

func notInMirror(names [][]byte, mirror string, size int) []string {
	idxs, _ := filepath.Glob(filepath.Join(mirror, "pack", "*.idx"))
	slices.SortFunc(idxs, func(a, b string) int { return int(fileSize(b) - fileSize(a)) })
	for _, idx := range idxs {
		if len(names) == 0 {
			break
		}
		names = withoutIdxNames(names, idx, size)
	}
	var out []string
	for _, n := range names {
		id := hex.EncodeToString(n)
		if _, err := os.Lstat(filepath.Join(mirror, id[:2], id[2:])); err != nil {
			out = append(out, id)
		}
	}
	return out
}

func withoutIdxNames(names [][]byte, idx string, size int) [][]byte {
	f, err := os.Open(idx)
	if err != nil {
		return names
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	n, err := readIdxHeader(r)
	if err != nil {
		return names
	}
	var out [][]byte
	known := make([]byte, size)
	i, read := 0, 0
	for i < len(names) && read < n {
		if _, err := io.ReadFull(r, known); err != nil {
			break
		}
		read++
		for i < len(names) && bytes.Compare(names[i], known) < 0 {
			out = append(out, names[i])
			i++
		}
		if i < len(names) && bytes.Equal(names[i], known) {
			i++
		}
	}
	return append(out, names[i:]...)
}

func fileSize(p string) int64 {
	info, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return info.Size()
}

func copyVerifiedObjects(ctx context.Context, t Tools, gitDir, pack string, ids []string, newHash func() hash.Hash) error {
	if len(ids) == 0 {
		return nil
	}
	dir, err := os.MkdirTemp("", "doriath-pack-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.Mkdir(filepath.Join(dir, "pack"), 0o700); err != nil {
		return err
	}
	base := strings.TrimSuffix(pack, ".pack")
	for _, ext := range []string{".pack", ".idx"} {
		if err := os.Symlink(base+ext, filepath.Join(dir, "pack", filepath.Base(base)+ext)); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, t.Git, "--git-dir", gitDir, "--work-tree", gitDir, "cat-file", "--batch")
	cmd.Env = append(os.Environ(), append(gitEnv, "GIT_OBJECT_DIRECTORY="+dir, "GIT_ALTERNATE_OBJECT_DIRECTORIES=")...)
	cmd.Stdin = strings.NewReader(strings.Join(ids, "\n") + "\n")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	r := bufio.NewReader(out)
	objects := filepath.Join(gitDir, "objects")
	for _, id := range ids {
		if err := copyObject(r, objects, id, newHash); err != nil {
			cancel()
			_ = cmd.Wait()
			return fmt.Errorf("object %s: %w", id, err)
		}
	}
	return cmd.Wait()
}

var objectTypes = []string{"commit", "tree", "blob", "tag"}

func copyObject(r *bufio.Reader, objects, id string, newHash func() hash.Hash) error {
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	fields := strings.Fields(line)
	if len(fields) != 3 || fields[0] != id || !slices.Contains(objectTypes, fields[1]) {
		return fmt.Errorf("git cat-file printed %q", strings.TrimSpace(line))
	}
	size, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || size < 0 {
		return fmt.Errorf("git cat-file printed %q", strings.TrimSpace(line))
	}
	dir := filepath.Join(objects, id[:2])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "tmp_obj_")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	h, z := newHash(), zlib.NewWriter(f)
	w := io.MultiWriter(h, z)
	if _, err := fmt.Fprintf(w, "%s %d\x00", fields[1], size); err != nil {
		f.Close()
		return err
	}
	if _, err := io.CopyN(w, r, size); err != nil {
		f.Close()
		return err
	}
	if b, err := r.ReadByte(); err != nil || b != '\n' {
		f.Close()
		return errors.New("git cat-file printed more than the object")
	}
	if err := z.Close(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != id {
		return fmt.Errorf("its content has the name %s", got)
	}
	if err := os.Chmod(f.Name(), 0o444); err != nil {
		return err
	}
	target := filepath.Join(dir, id[2:])
	if _, err := os.Lstat(target); err == nil {
		return nil
	}
	return os.Rename(f.Name(), target)
}

func removePack(pack string) []string {
	var removed []string
	matches, _ := filepath.Glob(strings.TrimSuffix(pack, ".pack") + ".*")
	for _, m := range matches {
		if os.Remove(m) == nil {
			removed = append(removed, m)
		}
	}
	return removed
}
