package profile_test

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/fnune/girdle/internal/config"
	"github.com/fnune/girdle/internal/modules"
	"github.com/fnune/girdle/internal/profile"
)

type snippet struct {
	file    string
	line    int
	heading string
	body    string
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
		case trimmed == "```toml":
			current = &snippet{file: filepath.Base(path), line: n, heading: heading}
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

// TestDocExamplesLoad keeps the examples in the docs loadable: a reader who
// copies one gets a file girdle accepts.
func TestDocExamplesLoad(t *testing.T) {
	var snippets []snippet
	for _, doc := range []string{"docs/configuration.md", "docs/install.md", "README.md"} {
		snippets = append(snippets, tomlSnippets(t, filepath.Join("..", "..", doc))...)
	}
	if len(snippets) < 3 {
		t.Fatalf("found %d toml examples in the docs; the extraction is broken", len(snippets))
	}
	for _, s := range snippets {
		t.Run(s.file+":"+s.heading, func(t *testing.T) {
			if s.heading == "config.toml keys" {
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
