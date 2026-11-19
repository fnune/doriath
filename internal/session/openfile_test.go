package session

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/profile"
)

func fileSession(t *testing.T, notifier approval.Notifier) (*testSession, *openedLinks, string) {
	t.Helper()
	s, opened := linkSession(t, notifier)
	notes := filepath.Join(s.home, "notes")
	if err := os.MkdirAll(filepath.Join(notes, "secret"), 0o755); err != nil {
		t.Fatal(err)
	}
	s.req.Profile.Mounts = []profile.Mount{
		{Path: notes, Mode: profile.ModeWrite},
		{Path: filepath.Join(notes, "secret"), Mode: profile.ModeHide},
	}
	return s, opened, notes
}

func openable(t *testing.T, path string, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func fileLink(path string) string {
	return (&url.URL{Scheme: "file", Path: path}).String()
}

func TestAFileThatTheJailShowsOpensOnceYouAllowIt(t *testing.T) {
	allow := approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingOnce}
	notifier := &answering{seen: make(chan approval.Request, 1), decision: &allow}
	s, opened, notes := fileSession(t, notifier)
	path := openable(t, filepath.Join(notes, "plan.md"), 0o644)
	if _, err := s.requestOpen(fileLink(path), "show the plan"); err != nil {
		t.Fatal(err)
	}
	req := <-notifier.seen
	if req.Kind != approval.KindOpen || req.Scope != "open file "+path || !strings.Contains(req.Details, path) {
		t.Errorf("request = %+v", req)
	}
	if len(opened.urls) != 1 || opened.urls[0] != path {
		t.Errorf("opened %v", opened.urls)
	}
}

func TestAFileThatAnAppCouldRunIsNotOpened(t *testing.T) {
	s, opened, notes := fileSession(t, allowing())
	link := filepath.Join(notes, "link.md")
	if err := os.Symlink(openable(t, filepath.Join(notes, "target.md"), 0o644), link); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		openable(t, filepath.Join(notes, "run.desktop"), 0o644):      "kinds of file",
		openable(t, filepath.Join(notes, "tool.jar"), 0o644):         "kinds of file",
		openable(t, filepath.Join(notes, "page.html"), 0o644):        "kinds of file",
		openable(t, filepath.Join(notes, "page.htm"), 0o644):         "kinds of file",
		openable(t, filepath.Join(notes, "drawing.svg"), 0o644):      "kinds of file",
		openable(t, filepath.Join(notes, "script.md"), 0o755):        "executable",
		openable(t, filepath.Join(notes, "secret", "env.md"), 0o644): "jail shows",
		openable(t, filepath.Join(s.home, "outside.md"), 0o644):      "jail shows",
		link:                               "symlink",
		notes:                              "regular file",
		filepath.Join(notes, "missing.md"): "symlink",
	} {
		if _, err := s.requestOpen(fileLink(path), ""); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", path, err, want)
		}
	}
	if _, err := s.requestOpen("file://other.example"+filepath.Join(notes, "target.md"), ""); err == nil || !strings.Contains(err.Error(), "this machine") {
		t.Errorf("a file on another host: err = %v", err)
	}
	if len(opened.urls) != 0 {
		t.Errorf("opened %v", opened.urls)
	}
}

func TestAFileThatBecomesExecutableAfterTheRequestIsNotOpened(t *testing.T) {
	s, opened, notes := fileSession(t, allowing())
	path := openable(t, filepath.Join(notes, "plan.md"), 0o644)
	u, _ := url.Parse(fileLink(path))
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.openFile(u); err == nil {
		t.Error("an executable file opened")
	}
	if len(opened.urls) != 0 {
		t.Errorf("opened %v", opened.urls)
	}
}
