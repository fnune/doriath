package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/session"
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
		if _, _, err := runningEntry("", nil); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}

	if err := os.WriteFile(entry, []byte(`{"pid":`+strconv.Itoa(os.Getpid())+`,"cwd":"/work","landlock":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dir, e, err := runningEntry("s1", nil)
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

func TestForwardChecksItsArgumentsBeforeLookingForASession(t *testing.T) {
	testPaths(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "usage: doriath forward"},
		{[]string{"3000", "4000"}, "usage: doriath forward"},
		{[]string{"http"}, `port "http": want a number from 1 to 65535`},
		{[]string{"3000"}, "no running sessions"},
		{[]string{"--session", "s9", "3000"}, "no running session s9; to list them, run: `doriath status`"},
	} {
		if err := cmdForward(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("forward %q = %v, want %q", tc.args, err, tc.want)
		}
	}
}

func TestParseInitMarksTheForwardsThatIdentifyTheCaller(t *testing.T) {
	forwards, command, err := parseInit([]string{
		"--forward", "3000=/run/a.sock", "--forward", "4000=/run/b.sock", "--identify", "4000", "--identify", "5000", "--", "claude", "--resume",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(forwards) != 2 || forwards[0].Identify || !forwards[1].Identify || forwards[1].Socket != "/run/b.sock" {
		t.Errorf("forwards = %+v", forwards)
	}
	if strings.Join(command, " ") != "claude --resume" {
		t.Errorf("command = %q", command)
	}
	if _, _, err := parseInit([]string{"--identify", "http"}); err == nil || !strings.Contains(err.Error(), `"http" is not a port number`) {
		t.Errorf("a named port = %v", err)
	}
}
