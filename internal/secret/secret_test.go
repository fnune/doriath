package secret

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

type fakeRunner struct {
	calls  int
	stdout string
	stderr string
	err    error
}

func (f *fakeRunner) Output(_ context.Context, _ []string) ([]byte, []byte, error) {
	f.calls++
	return []byte(f.stdout), []byte(f.stderr), f.err
}

type mapFiles struct{ fs fstest.MapFS }

func (m mapFiles) Stat(p string) (fs.FileInfo, error) { return m.fs.Stat(strings.TrimPrefix(p, "/")) }
func (m mapFiles) ReadFile(p string) ([]byte, error) {
	return m.fs.ReadFile(strings.TrimPrefix(p, "/"))
}

func TestCommandBackendIsCalledOnce(t *testing.T) {
	run := &fakeRunner{stdout: "tok\n"}
	s := NewConfigured(map[string]Backend{"gh": {Command: []string{"rbw", "get", "gh"}}}, run, mapFiles{})
	for range 3 {
		v, err := s.Get(context.Background(), "gh")
		if err != nil || string(v.Reveal()) != "tok" {
			t.Fatalf("Get = %q, %v", v.Reveal(), err)
		}
	}
	if run.calls != 1 {
		t.Fatalf("command ran %d times, want 1", run.calls)
	}
}

func TestFileBackendRefusesLoosePermissions(t *testing.T) {
	files := mapFiles{fstest.MapFS{
		"tight": {Data: []byte("abc\n"), Mode: 0o600},
		"loose": {Data: []byte("abc\n"), Mode: 0o644},
	}}
	s := NewConfigured(map[string]Backend{"tight": {File: "/tight"}, "loose": {File: "/loose"}}, &fakeRunner{}, files)
	if v, err := s.Get(context.Background(), "tight"); err != nil || string(v.Reveal()) != "abc" {
		t.Fatalf("tight = %q, %v", v.Reveal(), err)
	}
	if _, err := s.Get(context.Background(), "loose"); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("loose err = %v", err)
	}
}

func TestErrors(t *testing.T) {
	run := &fakeRunner{stderr: "vault is locked\nmore", err: errors.New("exit status 1")}
	s := NewConfigured(map[string]Backend{"locked": {Command: []string{"rbw", "get", "x"}}}, run, mapFiles{})
	_, err := s.Get(context.Background(), "locked")
	if err == nil || !strings.Contains(err.Error(), "vault is locked") || strings.Contains(err.Error(), "more") {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.Get(context.Background(), "missing"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("missing err = %v", err)
	}
	empty := NewConfigured(map[string]Backend{"e": {Command: []string{"true"}}}, &fakeRunner{stdout: "\n"}, mapFiles{})
	if _, err := empty.Get(context.Background(), "e"); err == nil {
		t.Fatal("an empty secret must be an error")
	}
}

func TestValueNeverPrints(t *testing.T) {
	v := NewValue([]byte("hunter2"))
	for _, s := range []string{fmt.Sprint(v), fmt.Sprintf("%v %+v %#v %s", v, v, v, v)} {
		if strings.Contains(s, "hunter2") {
			t.Fatalf("secret leaked: %s", s)
		}
	}
}

func TestBackendValidate(t *testing.T) {
	if (Backend{}).Validate() == nil || (Backend{File: "a", Command: []string{"b"}}).Validate() == nil {
		t.Fatal("want errors")
	}
	if (Backend{File: "a"}).Validate() != nil {
		t.Fatal("file alone is valid")
	}
}
