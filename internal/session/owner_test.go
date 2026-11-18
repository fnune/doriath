package session

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fnune/doriath/internal/vcs"
)

func fakeStat(t *testing.T, proc string, pid, start string) {
	t.Helper()
	dir := filepath.Join(proc, pid)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	line := pid + " (doriath (x) y) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 " + start + " 20 21\n"
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestARecordOfARunningSessionIsNotInterrupted(t *testing.T) {
	proc := t.TempDir()
	fakeStat(t, proc, "42", "1000")
	if !Running(proc, &vcs.Record{Owner: vcs.Owner{PID: 42, Start: 1000}}) {
		t.Error("the session that owns the record still runs")
	}
}

func TestARecordWhoseProcessIdWasReusedIsInterrupted(t *testing.T) {
	proc := t.TempDir()
	fakeStat(t, proc, "42", "2000")
	for _, rec := range []*vcs.Record{
		{Owner: vcs.Owner{PID: 42, Start: 1000}},
		{Owner: vcs.Owner{PID: 43, Start: 1000}},
		{},
	} {
		if Running(proc, rec) {
			t.Errorf("%+v counts as running", rec.Owner)
		}
	}
}

func TestTheOwnerOfThisProcessIsRunning(t *testing.T) {
	owner, err := processOwner("/proc", os.Getpid())
	if err != nil || owner.Start == 0 {
		t.Fatalf("owner = %+v, %v", owner, err)
	}
	if !Running("/proc", &vcs.Record{Owner: owner}) {
		t.Error("this process does not count as running")
	}
}
