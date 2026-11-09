package secret

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

type fakeRunner struct {
	calls    int
	stdout   string
	stderr   string
	err      error
	terminal []bool
}

func (f *fakeRunner) Output(_ context.Context, c Command) ([]byte, []byte, error) {
	f.calls++
	f.terminal = append(f.terminal, c.Terminal)
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
	s := NewConfigured(map[string]Backend{}, &fakeRunner{}, mapFiles{})
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
	if (Backend{File: "a"}).Validate() != nil || (Backend{Keyring: true}).Validate() != nil {
		t.Fatal("file alone and keyring alone are valid")
	}
	if (Backend{File: "a", Keyring: true}).Validate() == nil {
		t.Fatal("a keyring secret with a file is invalid")
	}
}

type fakeKeyring struct {
	entries map[string]string
	err     error
	reads   int
}

func (f *fakeKeyring) Read(profile, name string) (Value, error) {
	f.reads++
	if f.err != nil {
		return Value{}, f.err
	}
	v, ok := f.entries[profile+"/"+name]
	if !ok {
		return Value{}, ErrNotInKeyring
	}
	return NewValue([]byte(v)), nil
}

func (f *fakeKeyring) Write(profile, name string, v Value) error {
	f.entries[profile+"/"+name] = string(v.Reveal())
	return nil
}

func ownedByWork(string) string { return "work" }

func TestKeyringSecretsAreReadOnceFromTheEntryOfTheirProfile(t *testing.T) {
	kr := &fakeKeyring{entries: map[string]string{"work/forge": "tok\n", "home/forge": "other"}}
	s := NewConfigured(map[string]Backend{"forge": {Keyring: true}}, &fakeRunner{}, mapFiles{}).WithKeyring(kr, ownedByWork)
	for range 3 {
		v, err := s.Get(context.Background(), "forge")
		if err != nil || string(v.Reveal()) != "tok" {
			t.Fatalf("Get = %q, %v", v.Reveal(), err)
		}
	}
	if kr.reads != 1 {
		t.Errorf("reads = %d, want 1", kr.reads)
	}
}

func TestAMissingKeyringEntryNamesTheLoginCommand(t *testing.T) {
	s := NewConfigured(map[string]Backend{"forge": {Keyring: true}}, &fakeRunner{}, mapFiles{}).WithKeyring(&fakeKeyring{entries: map[string]string{}}, ownedByWork)
	_, err := s.Get(context.Background(), "forge")
	if want := "secret \"forge\" is not in the keyring: run `doriath profiles login work forge`"; err == nil || err.Error() != want {
		t.Errorf("err = %v, want %s", err, want)
	}
}

type fakeAsker struct {
	answer string
	err    error
	calls  int
}

func (f *fakeAsker) Ask(string) (Value, error) {
	f.calls++
	return NewValue([]byte(f.answer)), f.err
}

func TestAMissingKeyringEntryIsAskedForOnceAndKept(t *testing.T) {
	kr := &fakeKeyring{entries: map[string]string{}}
	ask := &fakeAsker{answer: "tok"}
	s := NewConfigured(map[string]Backend{"forge": {Keyring: true}}, &fakeRunner{}, mapFiles{}).WithKeyring(kr, ownedByWork).WithAsker(ask)
	v, err := s.Get(context.Background(), "forge")
	if err != nil || string(v.Reveal()) != "tok" || kr.entries["work/forge"] != "tok" {
		t.Fatalf("Get = %q, %v; keyring = %v", v.Reveal(), err, kr.entries)
	}
	if _, err := s.Get(context.Background(), "forge"); err != nil || ask.calls != 1 {
		t.Errorf("second Get: %v, asked %d times", err, ask.calls)
	}
}

func TestARetryDuringTheSessionDoesNotAskOnTheTerminal(t *testing.T) {
	kr := &fakeKeyring{entries: map[string]string{}}
	ask := &fakeAsker{err: errors.New("interrupted")}
	s := NewConfigured(map[string]Backend{"forge": {Keyring: true}}, &fakeRunner{}, mapFiles{}).WithKeyring(kr, ownedByWork).WithAsker(ask)
	if _, err := s.Get(context.Background(), "forge"); err == nil {
		t.Fatal("a failed answer gives the secret")
	}
	s.Retry("forge")
	_, err := s.Get(context.Background(), "forge")
	if ask.calls != 1 || err == nil || !strings.Contains(err.Error(), "doriath profiles login work forge") {
		t.Errorf("after Retry: asked %d times, err = %v", ask.calls, err)
	}
}

func TestAnEmptyAnswerIsNotKept(t *testing.T) {
	kr := &fakeKeyring{entries: map[string]string{}}
	s := NewConfigured(map[string]Backend{"forge": {Keyring: true}}, &fakeRunner{}, mapFiles{}).WithKeyring(kr, ownedByWork).WithAsker(&fakeAsker{answer: "\n"})
	if _, err := s.Get(context.Background(), "forge"); err == nil || len(kr.entries) != 0 {
		t.Errorf("err = %v, keyring = %v", err, kr.entries)
	}
}

func TestAKeyringThatFailsLeavesTheSecretUnavailable(t *testing.T) {
	broken := errors.New("read the keyring: no Secret Service")
	s := NewConfigured(map[string]Backend{"forge": {Keyring: true}}, &fakeRunner{}, mapFiles{}).WithKeyring(&fakeKeyring{err: broken}, ownedByWork)
	if _, err := s.Get(context.Background(), "forge"); !errors.Is(err, broken) {
		t.Errorf("err = %v, want %v", err, broken)
	}
	if _, ok := s.Unavailable()["forge"]; !ok {
		t.Error("the secret is not marked unavailable")
	}
	without := NewConfigured(map[string]Backend{"forge": {Keyring: true}}, &fakeRunner{}, mapFiles{})
	if _, err := without.Get(context.Background(), "forge"); err == nil || !strings.Contains(err.Error(), "the keyring is not available here") {
		t.Errorf("without a keyring: %v", err)
	}
}

type fakeOAuth struct{ calls int }

func (f *fakeOAuth) Token(_ context.Context, name string, _ OAuth) (Value, error) {
	f.calls++
	return NewValue([]byte(fmt.Sprintf("%s-%d", name, f.calls))), nil
}

func TestOAuthSecretsAreNotCached(t *testing.T) {
	tokens := &fakeOAuth{}
	c := NewConfigured(map[string]Backend{"notion": {OAuth: &OAuth{MCP: "https://mcp.notion.com/mcp"}}}, nil, nil).WithOAuth(tokens)
	for want := 1; want <= 2; want++ {
		v, err := c.Get(context.Background(), "notion")
		if err != nil || string(v.Reveal()) != fmt.Sprintf("notion-%d", want) {
			t.Fatalf("Get = %q, %v: a refreshed token must reach the proxy", v.Reveal(), err)
		}
	}
}

func TestOAuthBackendValidation(t *testing.T) {
	for name, b := range map[string]Backend{
		"mcp and issuer":       {OAuth: &OAuth{MCP: "https://a/", Issuer: "https://b/", ClientID: "c"}},
		"issuer without id":    {OAuth: &OAuth{Issuer: "https://b/"}},
		"mcp with a client id": {OAuth: &OAuth{MCP: "https://a/", ClientID: "c"}},
		"plain http":           {OAuth: &OAuth{MCP: "http://a/"}},
		"oauth and a file":     {File: "/x", OAuth: &OAuth{MCP: "https://a/"}},
	} {
		if b.Validate() == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if err := (Backend{OAuth: &OAuth{Issuer: "https://accounts.example.com", ClientID: "c"}}).Validate(); err != nil {
		t.Error(err)
	}
}

func TestAFailedCommandRunsAgainAfterThirtySecondsWithoutTheTerminal(t *testing.T) {
	start := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	c := &clock{t: start}
	run := &fakeRunner{err: errors.New("exit status 1")}
	s := NewConfigured(map[string]Backend{"gh": {Command: []string{"rbw", "get", "gh"}}}, run, mapFiles{}).WithClock(c.now)
	if _, err := s.Get(context.Background(), "gh"); err == nil || err.Error() != `secret "gh": command rbw: exit status 1` {
		t.Fatalf("err = %v", err)
	}
	run.err, run.stdout = nil, "tok"
	c.t = start.Add(10 * time.Second)
	if _, err := s.Get(context.Background(), "gh"); !errors.Is(err, ErrUnavailable) || run.calls != 1 {
		t.Fatalf("before the retry is due: calls = %d, err = %v", run.calls, err)
	}
	if got := s.Unavailable(); got["gh"] == nil {
		t.Errorf("unavailable = %v", got)
	}
	c.t = start.Add(31 * time.Second)
	if v, err := s.Get(context.Background(), "gh"); err != nil || string(v.Reveal()) != "tok" {
		t.Fatalf("after unlocking: %q, %v", v.Reveal(), err)
	}
	if want := []bool{true, false}; !slices.Equal(run.terminal, want) {
		t.Errorf("terminal = %v, want %v: a retry during the session must not take the agent's terminal", run.terminal, want)
	}
	if got := s.Unavailable(); len(got) != 0 {
		t.Errorf("unavailable after it worked = %v", got)
	}
}

func TestSecretKeepsAllButOneTrailingLineEnding(t *testing.T) {
	for out, want := range map[string]string{
		"tok\n":     "tok",
		"tok\r\n":   "tok",
		"tok":       "tok",
		"tok\n\n":   "tok\n",
		" tok \n":   " tok ",
		"a\nb\n":    "a\nb",
		"pass word": "pass word",
	} {
		s := NewConfigured(map[string]Backend{"s": {Command: []string{"cat"}}}, &fakeRunner{stdout: out}, mapFiles{})
		if v, err := s.Get(context.Background(), "s"); err != nil || string(v.Reveal()) != want {
			t.Errorf("%q: got %q, %v; want %q", out, v.Reveal(), err, want)
		}
	}
}

func TestErrorsSayWhatToDo(t *testing.T) {
	s := NewConfigured(map[string]Backend{
		"absent": {File: "/absent"},
		"login":  {OAuth: &OAuth{MCP: "https://mcp.example.com/mcp"}},
	}, &fakeRunner{}, mapFiles{fstest.MapFS{}})
	for name, want := range map[string]string{
		"missing": `secret "missing": unknown secret: add [secrets.missing] to the profile`,
		"absent":  `secret "absent": open absent: file does not exist`,
		"login":   `secret "login": OAuth logins are not available here`,
	} {
		if _, err := s.Get(context.Background(), name); err == nil || err.Error() != want {
			t.Errorf("%s: err = %v, want %s", name, err, want)
		}
	}
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestASecretThatExpiresIsReadAgainBeforeIt(t *testing.T) {
	start := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	c := &clock{t: start}
	run := &fakeRunner{stdout: `{"Version":1,"AccessKeyId":"A","Expiration":"2026-10-22T13:00:00Z"}`}
	s := NewConfigured(map[string]Backend{"aws": {Command: []string{"creds"}}}, run, mapFiles{}).WithClock(c.now)
	get := func() {
		t.Helper()
		if _, err := s.Get(context.Background(), "aws"); err != nil {
			t.Fatal(err)
		}
	}
	get()
	c.t = start.Add(54 * time.Minute)
	get()
	if run.calls != 1 {
		t.Fatalf("read again %d times before it was due", run.calls-1)
	}
	c.t = start.Add(56 * time.Minute)
	get()
	if run.calls != 2 {
		t.Fatalf("calls = %d: not read again 5 minutes before the expiry", run.calls)
	}
	if want := []bool{true, false}; !slices.Equal(run.terminal, want) {
		t.Errorf("terminal = %v: a refresh during the session must not take the terminal", run.terminal)
	}
}

func TestAFailedRefreshKeepsTheValueUntilItExpires(t *testing.T) {
	start := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	c := &clock{t: start}
	run := &fakeRunner{stdout: `{"Expiration":"2026-10-22T13:00:00Z"}`}
	s := NewConfigured(map[string]Backend{"aws": {Command: []string{"creds"}}}, run, mapFiles{}).WithClock(c.now)
	if _, err := s.Get(context.Background(), "aws"); err != nil {
		t.Fatal(err)
	}
	run.err, run.stderr = errors.New("exit status 1"), "session expired"
	c.t = start.Add(56 * time.Minute)
	if _, err := s.Get(context.Background(), "aws"); err != nil {
		t.Fatalf("the old value still works until 13:00: %v", err)
	}
	c.t = start.Add(56*time.Minute + 10*time.Second)
	if _, err := s.Get(context.Background(), "aws"); err != nil || run.calls != 2 {
		t.Fatalf("a failed refresh is retried after %s, not on every request: calls %d, %v", retryFailedRefreshAfter, run.calls, err)
	}
	c.t = start.Add(61 * time.Minute)
	if _, err := s.Get(context.Background(), "aws"); err == nil || !strings.Contains(Explained(err).Error(), "session expired") {
		t.Fatalf("an expired value must not be served: %v", err)
	}
}

func TestRefreshReadsATokenAgainOnItsSchedule(t *testing.T) {
	start := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	c := &clock{t: start}
	run := &fakeRunner{stdout: "ya29.token\n"}
	s := NewConfigured(map[string]Backend{"gcp": {Command: []string{"gcloud"}, Refresh: 45 * time.Minute}}, run, mapFiles{}).WithClock(c.now)
	for _, at := range []time.Duration{0, 44 * time.Minute, 46 * time.Minute} {
		c.t = start.Add(at)
		if _, err := s.Get(context.Background(), "gcp"); err != nil {
			t.Fatal(err)
		}
	}
	if run.calls != 2 {
		t.Errorf("calls = %d, want one read and one refresh", run.calls)
	}
	if err := (Backend{Command: []string{"x"}, Refresh: time.Second}).Validate(); err == nil {
		t.Error("a refresh under a minute must be refused")
	}
}

func TestAFailedCommandIsReportedByItsLastLineAfterPromptsAndProgress(t *testing.T) {
	run := &fakeRunner{stderr: "? Master password: [hidden]\nstack trace\nYou are not logged in.", err: errors.New("exit status 1")}
	s := NewConfigured(map[string]Backend{"locked": {Command: []string{"bw", "unlock"}}}, run, mapFiles{})
	if _, err := s.Get(context.Background(), "locked"); err == nil || !strings.HasSuffix(Explained(err).Error(), ": You are not logged in.") {
		t.Fatalf("err = %v", err)
	}
}

func TestWhatAFailedCommandPrintsStaysOutOfItsError(t *testing.T) {
	run := &fakeRunner{stderr: "wrong format: hunter2", err: errors.New("exit status 1")}
	s := NewConfigured(map[string]Backend{"token": {Command: []string{"wrapper"}}}, run, mapFiles{})
	if _, err := s.Get(context.Background(), "token"); err == nil || strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), "exit status 1") {
		t.Fatalf("err = %v", err)
	}
}

func TestAProvidedSecretReplacesAFailedOneForTheSession(t *testing.T) {
	run := &fakeRunner{err: errors.New("exit status 1")}
	s := NewConfigured(map[string]Backend{"acme": {Command: []string{"acme-token"}, Refresh: time.Minute}}, run, mapFiles{})
	if _, err := s.Get(context.Background(), "acme"); err == nil {
		t.Fatal("the failing command gave a value")
	}
	if err := s.Provide("acme", NewValue([]byte("tok"))); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Get(context.Background(), "acme"); err != nil || string(v.Reveal()) != "tok" {
		t.Fatalf("after provide: %q, %v", v.Reveal(), err)
	}
	if run.calls != 1 || len(s.Unavailable()) != 0 {
		t.Errorf("calls = %d, unavailable = %v: a provided value must not run the source again", run.calls, s.Unavailable())
	}
}

func TestOnlyANamedNonOAuthSecretCanBeProvided(t *testing.T) {
	s := NewConfigured(map[string]Backend{"linear": {OAuth: &OAuth{MCP: "https://mcp.linear.app/mcp"}}, "gh": {Command: []string{"gh"}}}, &fakeRunner{}, mapFiles{})
	for name, value := range map[string]string{"nope": "x", "linear": "x", "gh": "  "} {
		if err := s.Provide(name, NewValue([]byte(value))); err == nil {
			t.Errorf("provide %s = nil", name)
		}
	}
}
