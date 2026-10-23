package session

import (
	"cmp"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const largeScratch = 512 << 20

var toolParents = []string{".cache", ".local/share", ".local/state", ".config"}

type scratchFolder struct {
	path string
	size int64
	file bool
}

func largeScratchFolders(root string) []scratchFolder {
	sizes := map[string]int64{}
	files := map[string]bool{}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		folder := toolFolder(rel)
		sizes[folder] += info.Size()
		files[folder] = folder == rel
		return nil
	})
	var out []scratchFolder
	for path, size := range sizes {
		if size >= largeScratch {
			out = append(out, scratchFolder{path: "~/" + path, size: size, file: files[path]})
		}
	}
	slices.SortFunc(out, func(a, b scratchFolder) int { return cmp.Or(cmp.Compare(b.size, a.size), cmp.Compare(a.path, b.path)) })
	return out
}

func toolFolder(rel string) string {
	parts := strings.Split(rel, "/")
	for _, parent := range toolParents {
		n := strings.Count(parent, "/") + 1
		if len(parts) > n && strings.Join(parts[:n], "/") == parent {
			return strings.Join(parts[:n+1], "/")
		}
	}
	return parts[0]
}

func scratchNote(folders []scratchFolder, profile string) string {
	var total int64
	var list, lines strings.Builder
	for _, f := range folders {
		total += f.size
		fmt.Fprintf(&list, "\n%s: %s", f.path, gigabytes(f.size))
		if !f.file {
			fmt.Fprintf(&lines, "\n[[caches]]\npath = %s\n", strconv.Quote(f.path))
		}
	}
	return fmt.Sprintf("the agent wrote %s outside the profile's mounts and caches, and doriath deletes it now:%s\nTo keep it for later sessions, add to profile %s:%s",
		gigabytes(total), list.String(), profile, strings.TrimSuffix(lines.String(), "\n"))
}

func gigabytes(n int64) string {
	return fmt.Sprintf("%.1f GB", float64(n)/1e9)
}
