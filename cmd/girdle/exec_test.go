package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fnune/girdle/internal/session"
)

func TestRunningEntry(t *testing.T) {
	p := testPaths(t)
	startSession(t, p, "s1", "kitchen", time.Now())
	entry := filepath.Join(p.Sessions(), "s1", session.EntryFile)
	for name, tc := range map[string]struct{ entry, want string }{
		"still starting": {"", "the session is still starting"},
		"unreadable":     {"{", "read " + session.EntryFile},
		"jail ended":     {`{"pid":1073741824}`, "the session's jail has ended"},
	} {
		_ = os.Remove(entry)
		if tc.entry != "" {
			if err := os.WriteFile(entry, []byte(tc.entry), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := runningEntry(""); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}

	if err := os.WriteFile(entry, []byte(`{"pid":`+strconv.Itoa(os.Getpid())+`,"cwd":"/work","landlock":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dir, e, err := runningEntry("s1")
	if err != nil || dir != filepath.Join(p.Sessions(), "s1") || e.Cwd != "/work" || !e.Landlock {
		t.Errorf("running = %q, %+v, %v", dir, e, err)
	}
}

func TestEntryCwdKeepsYouWhereYouAreInsideTheSession(t *testing.T) {
	project := t.TempDir()
	sub := filepath.Join(project, "pkg")
	sibling := project + "-other"
	for _, d := range []string{sub, sibling} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ wd, want string }{
		{project, project},
		{sub, sub},
		{sibling, project},
	} {
		t.Chdir(tc.wd)
		if got := entryCwd(project); got != tc.want {
			t.Errorf("from %s = %s, want %s", tc.wd, got, tc.want)
		}
	}
}
