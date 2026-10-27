package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/vcs"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// movedRepo makes a repository whose main branch the agent moved from start
// to now.
func movedRepo(t *testing.T) (dir, start, now string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir = t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	git(t, dir, "commit", "-q", "--allow-empty", "-m", "start")
	start = git(t, dir, "rev-parse", "HEAD")
	git(t, dir, "commit", "-q", "--allow-empty", "-m", "the agent's")
	return dir, start, git(t, dir, "rev-parse", "HEAD")
}

func saveRecord(t *testing.T, p config.Paths, rec *vcs.Record) string {
	t.Helper()
	path := filepath.Join(p.Backups(), rec.Session+".json")
	if err := rec.Save(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func refExists(t *testing.T, dir, ref string) bool {
	t.Helper()
	return exec.Command("git", "-C", dir, "rev-parse", "--verify", "--quiet", ref).Run() == nil
}

func TestRestorePutsTheMovedBranchBack(t *testing.T) {
	p := testPaths(t)
	repo, start, _ := movedRepo(t)
	git(t, repo, "update-ref", vcs.BackupRef("s1", "refs/heads/main"), start)
	path := saveRecord(t, p, &vcs.Record{Session: "s1", Finished: true, Repos: []vcs.Repo{{
		Path: repo, GitDir: filepath.Join(repo, ".git"),
		Branches: map[string]string{"refs/heads/main": start},
		Moved:    []string{"refs/heads/main"},
	}}})

	var out bytes.Buffer
	if err := cmdRestore([]string{"s1"}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if want := repo + ": main is back at " + start[:7]; !strings.Contains(out.String(), want) {
		t.Errorf("restore says %q, want %q", out.String(), want)
	}
	if got := git(t, repo, "rev-parse", "main"); got != start {
		t.Errorf("main is at %s, want %s", got, start)
	}
	if refExists(t, repo, vcs.BackupRef("s1", "refs/heads/main")) {
		t.Error("the backup ref stays after a restore")
	}
	rec, err := vcs.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Repos[0].Moved) != 0 {
		t.Errorf("the record still lists moved branches: %v", rec.Repos[0].Moved)
	}
}

func TestRestoreErrors(t *testing.T) {
	testPaths(t)
	var out bytes.Buffer
	if err := cmdRestore(nil, &out); err == nil || !strings.Contains(err.Error(), "usage: doriath restore SESSION") {
		t.Errorf("without a session = %v", err)
	}
	if err := cmdRestore([]string{"gone"}, &out); err == nil || err.Error() != "restore: no record of session gone, or `doriath clean` removed it" {
		t.Errorf("an unknown session = %v", err)
	}
}

func clean(t *testing.T, answer string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := cmdClean(nil, strings.NewReader(answer), &out)
	return out.String(), err
}

func TestCleanFinishesAnInterruptedSessionAndDropsItsBackups(t *testing.T) {
	p := testPaths(t)
	repo, start, now := movedRepo(t)
	started := time.Date(2026, 10, 13, 9, 30, 0, 0, time.Local)
	path := saveRecord(t, p, &vcs.Record{Session: "s1", Started: started, Repos: []vcs.Repo{{
		Path: repo, GitDir: filepath.Join(repo, ".git"),
		Branches: map[string]string{"refs/heads/main": start},
	}}})
	backup := vcs.BackupRef("s1", "refs/heads/main")

	out, err := clean(t, "n\n")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{
		"doriath · session s1 · ended before doriath checked its repositories\n",
		"start values of session s1 (Oct 13 09:30): refs/heads/main\n",
		"Remove these? [y/N] ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("clean lacks %q:\n%s", want, out)
		}
	}
	if got := git(t, repo, "rev-parse", backup); got != start {
		t.Errorf("the backup ref is at %s, want the start value %s", got, start)
	}
	if got := git(t, repo, "rev-parse", "main"); got != now {
		t.Errorf("clean moved main to %s", got)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("answering no removes the record: %v", err)
	}

	out, err = clean(t, "y\n")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "checking them now") {
		t.Error("a finished session is checked again")
	}
	if refExists(t, repo, backup) {
		t.Error("the backup ref stays after clean")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the record stays after clean: %v", err)
	}
	if out, err := clean(t, ""); err != nil || out != "Nothing to clean.\n" {
		t.Errorf("clean once more = %q, %v", out, err)
	}
}

func TestCleanLeavesRunningSessionsAlone(t *testing.T) {
	p := testPaths(t)
	startSession(t, p, "s1", "kitchen", time.Now())
	running := saveRecord(t, p, &vcs.Record{Session: "s1", Started: time.Now()})
	ended := saveRecord(t, p, &vcs.Record{Session: "s2", Finished: true, Started: time.Date(2026, 10, 13, 9, 30, 0, 0, time.Local)})
	out, err := clean(t, "y\n")
	if err != nil || out != "record of session s2 (Oct 13 09:30)\nRemove these? [y/N] " {
		t.Errorf("clean = %q, %v", out, err)
	}
	if _, err := os.Stat(running); err != nil {
		t.Errorf("the record of a running session is gone: %v", err)
	}
	if _, err := os.Stat(ended); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the record of an ended session stays: %v", err)
	}
}

func TestCleanUsage(t *testing.T) {
	testPaths(t)
	for _, args := range [][]string{{"--caches", "a"}, {"extra"}} {
		if err := cmdClean(args, strings.NewReader(""), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("clean %q = %v", args, err)
		}
	}
}

func TestARunChecksOnlyTheInterruptedSessionsThatUseItsRepositories(t *testing.T) {
	p := testPaths(t)
	used, start, _ := movedRepo(t)
	other, otherStart, _ := movedRepo(t)
	usedPath := saveRecord(t, p, &vcs.Record{Session: "s1", Repos: []vcs.Repo{{
		Path: used, GitDir: filepath.Join(used, ".git"), Branches: map[string]string{"refs/heads/main": start},
	}}})
	otherPath := saveRecord(t, p, &vcs.Record{Session: "s2", Repos: []vcs.Repo{{
		Path: other, GitDir: filepath.Join(other, ".git"), Branches: map[string]string{"refs/heads/main": otherStart},
	}}})

	var out bytes.Buffer
	notes := finishInterruptedOf(p, &out, usesStores([]string{filepath.Join(used, ".git")}))

	if rec, err := vcs.Load(usedPath); err != nil || !rec.Finished {
		t.Errorf("the session on the same repository stays unchecked: %v\n%s", err, out.String())
	}
	if rec, err := vcs.Load(otherPath); err != nil || rec.Finished {
		t.Errorf("the run checked a session on another repository: %v", err)
	}
	if strings.Contains(out.String(), "session s2") {
		t.Errorf("the run printed the other session:\n%s", out.String())
	}
	want := "session s2 ended before doriath checked its repositories: " + other + ". doriath checks a repository when a session uses it, or at `doriath clean`"
	if len(notes) != 1 || notes[0] != want {
		t.Errorf("notes = %q, want %q", notes, want)
	}
}
