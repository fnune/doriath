package secret

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
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

func TestCommandBackendIsCalledOnce(t *testing.T) {
	run := &fakeRunner{stdout: "tok\n"}
	s := NewConfigured(map[string]Backend{"gh": {Command: []string{"rbw", "get", "gh"}}}, run)
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

func TestErrors(t *testing.T) {
	s := NewConfigured(map[string]Backend{}, &fakeRunner{})
	if _, err := s.Get(context.Background(), "missing"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("missing err = %v", err)
	}
	empty := NewConfigured(map[string]Backend{"e": {Command: []string{"true"}}}, &fakeRunner{stdout: "\n"})
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
	if (Backend{}).Validate() == nil || (Backend{Command: []string{"a"}, Keyring: true}).Validate() == nil {
		t.Fatal("want errors")
	}
	if (Backend{Command: []string{"a"}}).Validate() != nil || (Backend{Keyring: true}).Validate() != nil {
		t.Fatal("command alone and keyring alone are valid")
	}
	if (Backend{Command: []string{"a"}, Keyring: true}).Validate() == nil {
		t.Fatal("a keyring secret with a command is invalid")
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
	s := NewConfigured(map[string]Backend{"forge": {Keyring: true}}, &fakeRunner{}).WithKeyring(kr, ownedByWork)
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
	s := NewConfigured(map[string]Backend{"forge": {Keyring: true}}, &fakeRunner{}).WithKeyring(&fakeKeyring{entries: map[string]string{}}, ownedByWork)
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

func (f *fakeAsker) Ask(context.Context, string, string) (Value, error) {
	f.calls++
	return NewValue([]byte(f.answer)), f.err
}

func TestAMissingKeyringEntryIsAskedForOnceAndKept(t *testing.T) {
	kr := &fakeKeyring{entries: map[string]string{}}
	ask := &fakeAsker{answer: "tok"}
	s := NewConfigured(map[string]Backend{"forge": {Keyring: true}}, &fakeRunner{}).WithKeyring(kr, ownedByWork).WithAsker(ask)
	v, err := s.Get(context.Background(), "forge")
	if err != nil || string(v.Reveal()) != "tok" || kr.entries["work/forge"] != "tok" {
		t.Fatalf("Get = %q, %v; keyring = %v", v.Reveal(), err, kr.entries)
	}
	if _, err := s.Get(context.Background(), "forge"); err != nil || ask.calls != 1 {
		t.Errorf("second Get: %v, asked %d times", err, ask.calls)
	}
}

func TestAClosedDialogComesBackOnlyAfterRetry(t *testing.T) {
	kr := &fakeKeyring{entries: map[string]string{}}
	ask := &fakeAsker{err: errors.New("you closed the dialog without a value")}
	c := &clock{t: time.Unix(0, 0)}
	s := NewConfigured(map[string]Backend{"forge": {Keyring: true}}, &fakeRunner{}).WithKeyring(kr, ownedByWork).WithAsker(ask).WithClock(c.now)
	if _, err := s.Get(context.Background(), "forge"); err == nil {
		t.Fatal("a closed dialog gives the secret")
	}
	c.t = c.t.Add(time.Hour)
	_, err := s.Get(context.Background(), "forge")
	if ask.calls != 1 || err == nil || !strings.Contains(err.Error(), "doriath profiles login work forge") {
		t.Errorf("a later read: asked %d times, err = %v", ask.calls, err)
	}
	ask.err, ask.answer = nil, "tok"
	s.Retry("forge")
	if v, err := s.Get(context.Background(), "forge"); err != nil || string(v.Reveal()) != "tok" || ask.calls != 2 {
		t.Errorf("after Retry: %q, %v, asked %d times", v.Reveal(), err, ask.calls)
	}
}

func TestAnEmptyAnswerIsNotKept(t *testing.T) {
	kr := &fakeKeyring{entries: map[string]string{}}
	s := NewConfigured(map[string]Backend{"forge": {Keyring: true}}, &fakeRunner{}).WithKeyring(kr, ownedByWork).WithAsker(&fakeAsker{answer: "\n"})
	if _, err := s.Get(context.Background(), "forge"); err == nil || len(kr.entries) != 0 {
		t.Errorf("err = %v, keyring = %v", err, kr.entries)
	}
}

func TestAKeyringThatFailsLeavesTheSecretUnavailable(t *testing.T) {
	broken := errors.New("read the keyring: no Secret Service")
	s := NewConfigured(map[string]Backend{"forge": {Keyring: true}}, &fakeRunner{}).WithKeyring(&fakeKeyring{err: broken}, ownedByWork)
	if _, err := s.Get(context.Background(), "forge"); !errors.Is(err, broken) {
		t.Errorf("err = %v, want %v", err, broken)
	}
	if _, ok := s.Unavailable()["forge"]; !ok {
		t.Error("the secret is not marked unavailable")
	}
	without := NewConfigured(map[string]Backend{"forge": {Keyring: true}}, &fakeRunner{})
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
	c := NewConfigured(map[string]Backend{"notion": {OAuth: &OAuth{MCP: "https://mcp.notion.com/mcp"}}}, nil).WithOAuth(tokens)
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
		"oauth and a command":  {Command: []string{"x"}, OAuth: &OAuth{MCP: "https://a/"}},
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
	s := NewConfigured(map[string]Backend{"gh": {Command: []string{"rbw", "get", "gh"}}}, run).WithClock(c.now)
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
		s := NewConfigured(map[string]Backend{"s": {Command: []string{"cat"}}}, &fakeRunner{stdout: out})
		if v, err := s.Get(context.Background(), "s"); err != nil || string(v.Reveal()) != want {
			t.Errorf("%q: got %q, %v; want %q", out, v.Reveal(), err, want)
		}
	}
}

func TestErrorsSayWhatToDo(t *testing.T) {
	s := NewConfigured(map[string]Backend{
		"login": {OAuth: &OAuth{MCP: "https://mcp.example.com/mcp"}},
	}, &fakeRunner{})
	for name, want := range map[string]string{
		"missing": `secret "missing": unknown secret: add [secrets.missing] to the profile`,
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
	s := NewConfigured(map[string]Backend{"aws": {Command: []string{"creds"}}}, run).WithClock(c.now)
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
	s := NewConfigured(map[string]Backend{"aws": {Command: []string{"creds"}}}, run).WithClock(c.now)
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
	s := NewConfigured(map[string]Backend{"gcp": {Command: []string{"gcloud"}, Refresh: 45 * time.Minute}}, run).WithClock(c.now)
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
	s := NewConfigured(map[string]Backend{"locked": {Command: []string{"bw", "unlock"}}}, run)
	if _, err := s.Get(context.Background(), "locked"); err == nil || !strings.HasSuffix(Explained(err).Error(), ": You are not logged in.") {
		t.Fatalf("err = %v", err)
	}
}

func TestWhatAFailedCommandPrintsStaysOutOfItsError(t *testing.T) {
	run := &fakeRunner{stderr: "wrong format: hunter2", err: errors.New("exit status 1")}
	s := NewConfigured(map[string]Backend{"token": {Command: []string{"wrapper"}}}, run)
	if _, err := s.Get(context.Background(), "token"); err == nil || strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), "exit status 1") {
		t.Fatalf("err = %v", err)
	}
}

func TestAProvidedSecretReplacesAFailedOneForTheSession(t *testing.T) {
	run := &fakeRunner{err: errors.New("exit status 1")}
	s := NewConfigured(map[string]Backend{"acme": {Command: []string{"acme-token"}, Refresh: time.Minute}}, run)
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
	s := NewConfigured(map[string]Backend{"linear": {OAuth: &OAuth{MCP: "https://mcp.linear.app/mcp"}}, "gh": {Command: []string{"gh"}}}, &fakeRunner{})
	for name, value := range map[string]string{"nope": "x", "linear": "x", "gh": "  "} {
		if err := s.Provide(name, NewValue([]byte(value))); err == nil {
			t.Errorf("provide %s = nil", name)
		}
	}
}

type fakeApps struct {
	calls   int
	keys    []string
	err     error
	expires func(now time.Time) time.Time
	now     func() time.Time
}

func (f *fakeApps) Mint(_ context.Context, app GitHubApp, key Value) (Value, time.Time, error) {
	f.calls++
	f.keys = append(f.keys, string(key.Reveal()))
	if f.err != nil {
		return Value{}, time.Time{}, f.err
	}
	return NewValue([]byte(fmt.Sprintf("ghs_%d", f.calls))), f.expires(f.now()), nil
}

var testApp = GitHubApp{AppID: 7, Key: "key", Permissions: map[string]string{"contents": "write"}}

func TestAGitHubAppTokenIsMintedWithTheKeyAndRenewedBeforeItExpires(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)}
	apps := &fakeApps{now: c.now, expires: func(now time.Time) time.Time { return now.Add(time.Hour) }}
	run := &fakeRunner{stdout: "-----PEM-----\n"}
	s := NewConfigured(map[string]Backend{"app": {GitHubApp: &testApp}, "key": {Command: []string{"rbw", "get", "key"}}}, run).WithGitHubApps(apps).WithClock(c.now)
	get := func() string {
		v, err := s.Get(context.Background(), "app")
		if err != nil {
			t.Fatal(err)
		}
		return string(v.Reveal())
	}
	first, second := get(), get()
	if first != "ghs_1" || second != "ghs_1" || apps.calls != 1 {
		t.Fatalf("a token is minted once while it lasts: %d calls", apps.calls)
	}
	if apps.keys[0] != "-----PEM-----" || run.calls != 1 {
		t.Errorf("key = %q, key command ran %d times", apps.keys[0], run.calls)
	}
	c.t = c.t.Add(54 * time.Minute)
	if get() != "ghs_1" {
		t.Error("the token is renewed too early")
	}
	c.t = c.t.Add(2 * time.Minute)
	if get() != "ghs_2" || apps.calls != 2 {
		t.Errorf("the token is not renewed before it expires: %d calls", apps.calls)
	}
	if run.calls != 1 {
		t.Errorf("the key was read again: %d", run.calls)
	}
}

func TestAFailedRenewalKeepsTheTokenUntilItExpires(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)}
	apps := &fakeApps{now: c.now, expires: func(now time.Time) time.Time { return now.Add(time.Hour) }}
	s := NewConfigured(map[string]Backend{"app": {GitHubApp: &testApp}, "key": {Command: []string{"k"}}}, &fakeRunner{stdout: "pem"}).WithGitHubApps(apps).WithClock(c.now)
	if _, err := s.Get(context.Background(), "app"); err != nil {
		t.Fatal(err)
	}
	apps.err = errors.New("GitHub is down")
	c.t = c.t.Add(56 * time.Minute)
	if v, err := s.Get(context.Background(), "app"); err != nil || string(v.Reveal()) != "ghs_1" {
		t.Fatalf("before expiry = %q, %v", v.Reveal(), err)
	}
	c.t = c.t.Add(10 * time.Minute)
	if _, err := s.Get(context.Background(), "app"); err == nil || !strings.Contains(err.Error(), `secret "app": GitHub is down`) {
		t.Errorf("after expiry: %v", err)
	}
}

func TestAGitHubAppSecretWithoutAKeyOrAMinterIsUnavailable(t *testing.T) {
	apps := &fakeApps{expires: func(now time.Time) time.Time { return now }, now: time.Now}
	missing := NewConfigured(map[string]Backend{"app": {GitHubApp: &testApp}}, &fakeRunner{}).WithGitHubApps(apps)
	if _, err := missing.Get(context.Background(), "app"); err == nil || !strings.Contains(err.Error(), `the private key in "key"`) || !errors.Is(err, ErrUnknown) {
		t.Errorf("a key that is not a secret: %v", err)
	}
	without := NewConfigured(map[string]Backend{"app": {GitHubApp: &testApp}, "key": {Command: []string{"k"}}}, &fakeRunner{stdout: "pem"})
	if _, err := without.Get(context.Background(), "app"); err == nil || !strings.Contains(err.Error(), "GitHub App tokens are not available here") {
		t.Errorf("without a minter: %v", err)
	}
}

func TestGitHubAppValidation(t *testing.T) {
	with := func(change func(*GitHubApp)) Backend {
		a := testApp
		a.Permissions = map[string]string{"contents": "write"}
		change(&a)
		return Backend{GitHubApp: &a}
	}
	if err := with(func(*GitHubApp) {}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := with(func(a *GitHubApp) { a.Repositories = []string{"fnune/a", "Fnune/b.c"} }).Validate(); err != nil {
		t.Errorf("repositories: %v", err)
	}
	for name, c := range map[string]struct {
		b    Backend
		want string
	}{
		"no app id":                {with(func(a *GitHubApp) { a.AppID = 0 }), "set app_id"},
		"no key":                   {with(func(a *GitHubApp) { a.Key = "" }), "set key"},
		"no permissions":           {with(func(a *GitHubApp) { a.Permissions = nil }), "set permissions"},
		"bad permission name":      {with(func(a *GitHubApp) { a.Permissions = map[string]string{"Pull-Requests": "write"} }), `permission "Pull-Requests"`},
		"bad permission level":     {with(func(a *GitHubApp) { a.Permissions = map[string]string{"contents": "all"} }), `contents = "all": want read, write or admin`},
		"repository without owner": {with(func(a *GitHubApp) { a.Repositories = []string{"doriath"} }), `want owner/repo`},
		"two owners":               {with(func(a *GitHubApp) { a.Repositories = []string{"a/x", "b/y"} }), "different owners"},
		"with a command":           {Backend{Command: []string{"x"}, GitHubApp: &testApp}, "exactly one of command, keyring, oauth or github_app"},
		"with refresh":             {Backend{GitHubApp: &testApp, Refresh: time.Hour}, "renews before it expires"},
	} {
		if err := c.b.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}

func TestWithoutNameStripsOnlyTheLeadingName(t *testing.T) {
	for in, want := range map[string]string{
		`secret "a:b": no GitHub remote, so no token`:      "no GitHub remote, so no token",
		`secret "a" is empty`:                              "is empty",
		`secret "a\"b": command x: failed`:                 "command x: failed",
		`secret "a": the private key: secret "k": missing`: `the private key: secret "k": missing`,
		`command x: failed`:                                "command x: failed",
	} {
		if got := WithoutName(errors.New(in)); got != want {
			t.Errorf("%s = %q, want %q", in, got, want)
		}
	}
}
