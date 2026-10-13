package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddEgressHostWritesOneHeader(t *testing.T) {
	dir := t.TempDir()
	for _, h := range []string{"a.example", "b.example", "c.example"} {
		if err := AddEgressHost(dir, "p", h); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(filepath.Join(dir, LocalFile("p")))
	if n := strings.Count(string(data), "Written by girdle"); n != 1 {
		t.Fatalf("%d headers:\n%s", n, data)
	}
}
