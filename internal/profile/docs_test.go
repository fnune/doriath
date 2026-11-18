package profile_test

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/modules"
	"github.com/fnune/doriath/internal/profile"
)

type snippet struct {
	file    string
	line    int
	heading string
	fence   string
	body    string
}

func (s snippet) userConfig() bool {
	return s.heading == "config.toml keys" || strings.Contains(s.fence, "config.toml")
}

func tomlSnippets(t *testing.T, path string) []snippet {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var (
		out     []snippet
		heading string
		current *snippet
		body    strings.Builder
	)
	lines := bufio.NewScanner(f)
	for n := 1; lines.Scan(); n++ {
		line := lines.Text()
		trimmed := strings.TrimSpace(line)
		switch {
		case current != nil && trimmed == "```":
			current.body = body.String()
			out = append(out, *current)
			current = nil
		case current != nil:
			body.WriteString(line + "\n")
		case trimmed == "```toml" || strings.HasPrefix(trimmed, "```toml "):
			current = &snippet{file: filepath.Base(path), line: n, heading: heading, fence: trimmed}
			body.Reset()
		case strings.HasPrefix(line, "#"):
			heading = strings.TrimSpace(strings.TrimLeft(line, "#"))
		}
	}
	if err := lines.Err(); err != nil {
		t.Fatal(err)
	}
	if current != nil {
		t.Fatalf("%s:%d: unterminated toml block", path, current.line)
	}
	return out
}

func TestDocExamplesLoad(t *testing.T) {
	root := filepath.Join("..", "..")
	docs := []string{filepath.Join(root, "README.md"), filepath.Join(root, "internal", "guide", "profile.md")}
	err := filepath.WalkDir(filepath.Join(root, "site", "src", "content", "docs"), func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && (strings.HasSuffix(path, ".md") || strings.HasSuffix(path, ".mdx")) {
			docs = append(docs, path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var snippets []snippet
	for _, doc := range docs {
		snippets = append(snippets, tomlSnippets(t, doc)...)
	}
	if len(snippets) < 3 {
		t.Fatalf("found %d toml examples in the docs; the extraction is broken", len(snippets))
	}
	for _, s := range snippets {
		t.Run(s.file+":"+s.heading, func(t *testing.T) {
			if s.userConfig() {
				path := filepath.Join(t.TempDir(), "config.toml")
				if err := os.WriteFile(path, []byte(s.body), 0o600); err != nil {
					t.Fatal(err)
				}
				if _, err := config.LoadUser(path); err != nil {
					t.Errorf("%s:%d: %v", s.file, s.line, err)
				}
				return
			}
			l := &profile.Loader{
				Profiles: fstest.MapFS{"example.toml": {Data: []byte(s.body)}},
				Modules:  []fs.FS{modules.FS},
				Home:     "/home/u",
			}
			if _, err := l.Load("example"); err != nil {
				t.Errorf("%s:%d: %v", s.file, s.line, err)
			}
		})
	}
}
