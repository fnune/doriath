package session

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fnune/doriath/internal/jailinit"
	"github.com/fnune/doriath/internal/profile"
)

const (
	maxArchiveBytes  = 1 << 30
	maxLibraryBytes  = 64 << 20
	maxLibraryBudget = 1 << 30
	maxSegments      = 4096
)

type segmentKey struct{ offset, length uint64 }

// codeArchives holds the executable pages of every native library inside the
// archives that a profile names. A program that unpacks a library from an
// archive into a temporary folder then runs code that the person already
// trusts.
//
// It compares memory, not files. The program deletes the library after it
// loads it, and the kernel lets only a privileged process open a deleted
// mapped file through /proc/PID/map_files. Reading /proc/PID/mem needs only
// that doriath started the process.
type codeArchives struct {
	procRoot string
	pageSize uint64
	segments map[segmentKey]map[[sha256.Size]byte]struct{}
	count    int
	hostPID  func(jailPID int) (int, error)
}

func newCodeArchives(procRoot string) *codeArchives {
	return &codeArchives{procRoot: procRoot, pageSize: uint64(os.Getpagesize()), segments: map[segmentKey]map[[sha256.Size]byte]struct{}{}, hostPID: func(pid int) (int, error) { return pid, nil }}
}

func pinArchives(p *profile.Profile, home, cacheRoot, procRoot string, writable []string) (*codeArchives, []string) {
	out := newCodeArchives(procRoot)
	var notes []string
	budget := int64(maxLibraryBudget)
	for _, pattern := range p.CodeArchives {
		for _, jailPath := range globInJail(p, home, cacheRoot, pattern) {
			source, ok := hostSource(p, home, cacheRoot, jailPath)
			if !ok {
				continue
			}
			n, err := out.addArchive(source, &budget)
			if err != nil {
				notes = append(notes, fmt.Sprintf("%s is not trusted as a source of native code: %v", shortPath(jailPath), err))
				continue
			}
			if n > 0 && inAny(source, writable) {
				notes = append(notes, fmt.Sprintf("the agent can write %s: a file that it puts there gets no trust in this session, but the next session trusts the libraries in it", shortPath(jailPath)))
			}
		}
	}
	return out, notes
}

func inAny(path string, roots []string) bool {
	for _, r := range roots {
		if path == r || strings.HasPrefix(path, r+"/") {
			return true
		}
	}
	return false
}

func (c *codeArchives) addArchive(path string, budget *int64) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxArchiveBytes {
		return 0, fmt.Errorf("it is not a regular file of at most %d MiB", maxArchiveBytes>>20)
	}
	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		return 0, err
	}
	added := 0
	for _, entry := range zr.File {
		if !isLibraryName(entry.Name) || entry.UncompressedSize64 > maxLibraryBytes || int64(entry.UncompressedSize64) > *budget {
			continue
		}
		data, ok := readEntry(entry)
		if !ok {
			continue
		}
		*budget -= int64(len(data))
		n, err := c.addLibrary(data)
		if err != nil {
			return added, err
		}
		added += n
	}
	return added, nil
}

func isLibraryName(name string) bool {
	base := filepath.Base(name)
	return strings.HasSuffix(base, ".so") || strings.Contains(base, ".so.")
}

func readEntry(entry *zip.File) ([]byte, bool) {
	r, err := entry.Open()
	if err != nil {
		return nil, false
	}
	defer func() { _ = r.Close() }()
	data, err := io.ReadAll(io.LimitReader(r, maxLibraryBytes+1))
	return data, err == nil && len(data) <= maxLibraryBytes
}

func (c *codeArchives) addLibrary(data []byte) (added int, err error) {
	defer func() {
		if recover() != nil {
			added, err = 0, nil
		}
	}()
	f, perr := elf.NewFile(bytes.NewReader(data))
	if perr != nil {
		return 0, nil
	}
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD || prog.Flags&elf.PF_X == 0 {
			continue
		}
		if c.count >= maxSegments {
			return added, fmt.Errorf("it holds more than the %d code segments that doriath reads", maxSegments)
		}
		start := prog.Off &^ (c.pageSize - 1)
		length := alignUp(prog.Off-start+prog.Filesz, c.pageSize)
		expected := make([]byte, length)
		if start < uint64(len(data)) {
			copy(expected, data[start:])
		}
		key := segmentKey{start, length}
		if c.segments[key] == nil {
			c.segments[key] = map[[sha256.Size]byte]struct{}{}
		}
		c.segments[key][sha256.Sum256(expected)] = struct{}{}
		c.count++
		added++
	}
	return added, nil
}

func alignUp(n, to uint64) uint64 { return (n + to - 1) &^ (to - 1) }

func (c *codeArchives) trusts(pid int, code jailinit.MappedFile) bool {
	return c.check(pid, code) == nil
}

func (c *codeArchives) check(pid int, code jailinit.MappedFile) error {
	if c == nil || c.count == 0 {
		return errors.New("the profile pins no archive")
	}
	lo, hi, ok := strings.Cut(code.Range, "-")
	start, err1 := strconv.ParseUint(lo, 16, 63)
	end, err2 := strconv.ParseUint(hi, 16, 63)
	if !ok || err1 != nil || err2 != nil || end <= start || end-start > maxLibraryBytes {
		return fmt.Errorf("the mapping %q is not a range of at most %d MiB", code.Range, maxLibraryBytes>>20)
	}
	want := c.segments[segmentKey{code.Offset, end - start}]
	if len(want) == 0 {
		return fmt.Errorf("no archived library has code at offset %#x with length %#x", code.Offset, end-start)
	}
	hostPID, err := c.hostPID(pid)
	if err != nil {
		return err
	}
	mem, err := os.Open(filepath.Join(c.procRoot, strconv.Itoa(hostPID), "mem"))
	if err != nil {
		return fmt.Errorf("doriath cannot read the memory of the process: %w", err)
	}
	defer func() { _ = mem.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.NewSectionReader(mem, int64(start), int64(end-start)))
	if err != nil {
		return fmt.Errorf("doriath cannot read the pages of the mapping: %w", err)
	}
	if uint64(n) != end-start {
		return errors.New("doriath read fewer pages than the mapping holds")
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	if _, trusted := want[sum]; !trusted {
		return errors.New("its pages match no archived library")
	}
	return nil
}
