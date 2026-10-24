package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/jail"
	"github.com/fnune/doriath/internal/vcstools"
	jjtool "github.com/fnune/doriath/internal/vcstools/jj"
)

func TestJJRunsGitThroughDoriathInTheJail(t *testing.T) {
	s := newTestSession(t, nil)
	s.jailDir = t.TempDir()
	s.deps.VCS = []vcstools.Tool{jjtool.New(s.home, osHost{}.Kind)}
	for range 2 {
		if err := s.writeVCSFiles(); err != nil {
			t.Fatalf("writing the files twice must work too: %v", err)
		}
	}
	if target, err := os.Readlink(filepath.Join(s.jailDir, JJGit)); err != nil || target != jail.ExePath {
		t.Errorf("%s links to %q, %v", JJGit, target, err)
	}
	config, err := os.ReadFile(filepath.Join(s.jailDir, "jj.toml"))
	if err != nil || !strings.Contains(string(config), jail.InJail(JJGit)) {
		t.Errorf("jj.toml = %s, %v", config, err)
	}
}
