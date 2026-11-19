package session

import (
	"debug/elf"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/fnune/doriath/internal/jail"
	"github.com/fnune/doriath/internal/jailinit"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/proxy"
)

type pins struct {
	programs map[string]jailinit.FileID
	code     map[string]jailinit.FileID
	archives *codeArchives
	store    map[string]struct{}
	writable []string
}

const nixStore = "/nix/store"

func snapshotStore(dir string) map[string]struct{} {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		out[e.Name()] = struct{}{}
	}
	return out
}

func (ps pins) systemPath(path string) bool {
	if !profile.UnderTrustedRoot(path) || inAny(path, ps.writable) {
		return false
	}
	if ps.store == nil {
		return true
	}
	name, ok := strings.CutPrefix(path, nixStore+"/")
	if !ok {
		return true
	}
	name, _, _ = strings.Cut(name, "/")
	_, known := ps.store[name]
	return known
}

const maxPinnedCode = 10000

func pinBinaries(p *profile.Profile, home, cacheRoot string, writable []string) (pins, []string) {
	out := pins{programs: map[string]jailinit.FileID{}, code: map[string]jailinit.FileID{}, writable: writable}
	if p.NixDaemon {
		out.store = snapshotStore(nixStore)
		if out.store == nil {
			out.store = map[string]struct{}{}
		}
	}
	var notes []string
	for _, pattern := range p.BinaryPaths() {
		for _, jailPath := range globInJail(p, home, cacheRoot, pattern) {
			if out.systemPath(jailPath) {
				continue
			}
			source, ok := hostSource(p, home, cacheRoot, jailPath)
			if !ok {
				continue
			}
			info, err := os.Lstat(source)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			if isScript(source) {
				notes = append(notes, fmt.Sprintf("%s is a script: the kernel names its interpreter, so the script never matches by path", shortPath(jailPath)))
				continue
			}
			out.programs[jailPath] = jailinit.FileIDOf(info)
			out.pinFolder(filepath.Dir(jailPath), filepath.Dir(source))
			for _, rel := range libraryFolders(runpaths(source)) {
				out.pinFolder(filepath.Join(filepath.Dir(jailPath), rel), filepath.Join(filepath.Dir(source), rel))
			}
			if slices.ContainsFunc(writable, func(w string) bool { return source == w || strings.HasPrefix(source, w+"/") }) {
				notes = append(notes, fmt.Sprintf("the agent can write %s: a file that it puts there gets no credential in this session, but the next session trusts it", shortPath(jailPath)))
			}
		}
	}
	return out, notes
}

func (ps pins) pinLibraries(p *profile.Profile, home, cacheRoot string, writable []string) []string {
	var notes []string
	for _, pattern := range p.CodeLibraries {
		for _, jailPath := range globInJail(p, home, cacheRoot, pattern) {
			source, ok := hostSource(p, home, cacheRoot, jailPath)
			if !ok {
				continue
			}
			info, err := os.Lstat(source)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			ps.code[jailPath] = jailinit.FileIDOf(info)
			if inAny(source, writable) {
				notes = append(notes, fmt.Sprintf("the agent can write %s: a file that it puts there gets no trust in this session, but the next session trusts it", shortPath(jailPath)))
			}
		}
	}
	return notes
}

func (ps pins) untrusted(id proxy.Identity) string {
	if id.Exe == "" || ps.systemPath(id.Exe) {
		return ps.foreignCode(id)
	}
	pinned, ok := ps.programs[id.Exe]
	switch {
	case !ok:
		return fmt.Sprintf("%s is not a file that the profile names, as it was when the session started", id.Exe)
	case id.File != pinned:
		return fmt.Sprintf("%s is not the file it was when the session started", id.Exe)
	}
	return ps.foreignCode(id)
}

func (ps pins) foreignCode(id proxy.Identity) string {
	for _, code := range id.Code {
		if file, pinned := ps.code[code.Path]; (pinned && file == code.File) || ps.systemPath(code.Path) {
			continue
		}
		reason := ps.archives.check(id.PID, code)
		if reason == nil {
			continue
		}
		return fmt.Sprintf("%s runs code from %s, which is outside the system paths and not as it was when the session started (not from a pinned archive: %v)", id.Exe, code.Path, reason)
	}
	return ""
}

func (ps pins) pinFolder(jailDir, sourceDir string) {
	_ = filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || len(ps.code) >= maxPinnedCode {
			return filepath.SkipDir
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			ps.code[filepath.Join(jailDir, strings.TrimPrefix(path, sourceDir))] = jailinit.FileIDOf(info)
		}
		return nil
	})
}

const maxDynamicData = 64 << 20

func runpaths(path string) (out []string) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	f, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	dynamic := f.SectionByType(elf.SHT_DYNAMIC)
	if dynamic == nil || dynamic.Size > maxDynamicData || int(dynamic.Link) >= len(f.Sections) || f.Sections[dynamic.Link].Size > maxDynamicData {
		return nil
	}
	for _, tag := range []elf.DynTag{elf.DT_RUNPATH, elf.DT_RPATH} {
		entries, _ := f.DynString(tag)
		for _, e := range entries {
			out = append(out, strings.Split(e, ":")...)
		}
	}
	return out
}

func libraryFolders(runpaths []string) []string {
	var out []string
	for _, entry := range runpaths {
		rest, ok := strings.CutPrefix(entry, "$ORIGIN")
		if !ok {
			rest, ok = strings.CutPrefix(entry, "${ORIGIN}")
		}
		if !ok {
			continue
		}
		rel := filepath.Clean("." + rest)
		if rel == "." || strings.HasPrefix(rel, "../..") || rel == ".." {
			continue
		}
		if !slices.Contains(out, rel) {
			out = append(out, rel)
		}
	}
	return out
}

func isScript(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 2)
	n, _ := f.Read(head)
	return n == 2 && string(head) == "#!"
}

func hostSource(p *profile.Profile, home, cacheRoot, jailPath string) (string, bool) {
	var deepest string
	visible, cached := false, false
	consider := func(root string, isCache, shown bool) {
		if (jailPath == root || strings.HasPrefix(jailPath, root+"/")) && len(root) >= len(deepest) {
			deepest, cached, visible = root, isCache, shown
		}
	}
	for _, m := range p.Mounts {
		consider(m.Path, false, m.Mode != profile.ModeHide)
	}
	for _, c := range p.Caches {
		consider(c.Path, true, true)
	}
	switch {
	case deepest == "" || !visible:
		return "", false
	case cached:
		return filepath.Join(jail.CacheSource(cacheRoot, deepest, home), strings.TrimPrefix(jailPath, deepest)), true
	}
	return jailPath, true
}

func globInJail(p *profile.Profile, home, cacheRoot, pattern string) []string {
	for _, c := range p.Caches {
		if rest, ok := strings.CutPrefix(pattern, c.Path+"/"); ok {
			source := jail.CacheSource(cacheRoot, c.Path, home)
			matches, _ := filepath.Glob(filepath.Join(source, rest))
			for i, m := range matches {
				matches[i] = filepath.Join(c.Path, strings.TrimPrefix(m, source))
			}
			return matches
		}
	}
	matches, _ := filepath.Glob(pattern)
	return matches
}
