package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/oauth"
	"github.com/fnune/doriath/internal/secret"
	"github.com/fnune/doriath/internal/session"
)

func profiles(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := cmdProfiles(args, strings.NewReader(""), &out)
	return out.String(), err
}

func TestProfilesList(t *testing.T) {
	p := testPaths(t)
	if out, err := profiles(t); err != nil || !strings.Contains(out, "No profiles in "+p.Profiles()) {
		t.Fatalf("empty list = %q, %v", out, err)
	}
	writeProfile(t, p, "kitchen", `description = "Kitchen"
modules = ["go"]
`)
	writeProfile(t, p, "broken", `modules = ["no-such-module"]`)
	out, err := profiles(t, "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "kitchen\tKitchen\n") {
		t.Errorf("list = %q", out)
	}
	if !strings.Contains(out, "broken\t(error: ") {
		t.Errorf("a broken profile is listed with its error: %q", out)
	}
}

func TestProfilesShow(t *testing.T) {
	p := testPaths(t)
	writeProfile(t, p, "kitchen", `description = "Kitchen"
modules = ["go"]

[egress]
allow = ["example.com"]
`)
	text, err := profiles(t, "show", "kitchen")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"kitchen: Kitchen", "Modules: go", "Hosts", "example.com", "profile", "proxy.golang.org", "go"} {
		if !strings.Contains(text, want) {
			t.Errorf("show lacks %q:\n%s", want, text)
		}
	}
	if _, err := profiles(t, "show", "missing"); err == nil {
		t.Error("show of a missing profile must fail")
	}
	if _, err := profiles(t, "nonsense"); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Errorf("unknown subcommand = %v", err)
	}
}

func TestProfilesEdit(t *testing.T) {
	p := testPaths(t)
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "true")
	var out bytes.Buffer
	if err := cmdProfiles([]string{"edit", "fresh"}, strings.NewReader(""), &out); err != nil {
		t.Fatalf("the template is not a valid profile: %v\n%s", err, out.String())
	}
	if info, err := os.Stat(filepath.Join(p.Profiles(), "fresh.toml")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("new profile: %v, %v", info, err)
	}

	writeProfile(t, p, "broken", `modules = []`)
	t.Setenv("EDITOR", `sed -i 's/\[\]/["bsae"]/'`)
	out.Reset()
	err := cmdProfiles([]string{"edit", "broken"}, strings.NewReader("n\n"), &out)
	if err == nil || !strings.Contains(out.String(), "Edit again?") {
		t.Fatalf("an invalid edit must ask and then fail: %v\n%s", err, out.String())
	}
}

func TestProfilesEditOpensAProfileInAFolder(t *testing.T) {
	p := testPaths(t)
	nested := filepath.Join(p.Profiles(), "private", "nested.toml")
	if err := os.MkdirAll(filepath.Dir(nested), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nested, []byte(`modules = []`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", `sed -i 's/\[\]/["vcs-readwrite"]/'`)
	var out bytes.Buffer
	if err := cmdProfiles([]string{"edit", "nested"}, strings.NewReader(""), &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if data, err := os.ReadFile(nested); err != nil || !strings.Contains(string(data), "vcs-readwrite") {
		t.Fatalf("the nested file was not edited: %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(p.Profiles(), "nested.toml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("edit created a second file: %v", err)
	}
}

func approvals(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := cmdApprovals(context.Background(), args, realClock{}, &out)
	return out.String(), err
}

func TestApprovalsListAllowDeny(t *testing.T) {
	p := testPaths(t)
	if out, err := approvals(t); err != nil || out != "No pending requests.\n" {
		t.Fatalf("no sessions = %q, %v", out, err)
	}

	first := startSession(t, p, "s1", "kitchen", time.Now().Add(-time.Minute))
	second := startSession(t, p, "s2", "garden", time.Now())
	pushID, push := first.submit(t, "Push to origin", "git push origin main\nwith tags")
	dropID, drop := second.submit(t, "Drop the table", "")

	out, err := approvals(t, "list")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ID", "EXPIRES IN", pushID, "kitchen", "Push to origin", dropID, "garden", "Drop the table",
		pushID + ": git push origin main\n    with tags",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}

	if _, err := approvals(t, "allow", pushID, "--for", "session"); err != nil {
		t.Fatal(err)
	}
	if d := receive(t, push); d.Verdict != approval.VerdictAllow || d.Lasting != approval.LastingSession || d.By != "cli" {
		t.Errorf("allow = %+v", d)
	}
	if _, err := approvals(t, "deny", dropID, "--reason", "not today"); err != nil {
		t.Fatal(err)
	}
	if d := receive(t, drop); d.Verdict != approval.VerdictDeny || d.Lasting != "" || d.Reason != "not today" || d.By != "cli" {
		t.Errorf("deny = %+v", d)
	}

	if _, err := approvals(t, "allow", pushID); err == nil || !strings.Contains(err.Error(), "no pending request") {
		t.Errorf("deciding twice = %v", err)
	}
	if _, err := approvals(t, "allow"); err == nil {
		t.Error("allow without an id must fail")
	}
	if _, err := approvals(t, "frobnicate"); err == nil {
		t.Error("unknown subcommand must fail")
	}
}

func TestApprovalsAllowFor(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	d, err := lastingDecision(approval.VerdictAllow, "30m", now)
	if err != nil || d.Lasting != approval.LastingUntil || !d.Until.Equal(now.Add(30*time.Minute)) {
		t.Errorf("30m = %+v, %v", d, err)
	}
	if d, err := lastingDecision(approval.VerdictDeny, "session", now); err != nil || d.Verdict != approval.VerdictDeny || d.Lasting != approval.LastingSession {
		t.Errorf("deny --for session = %+v, %v", d, err)
	}
	for _, bad := range []string{"forever", "profile", "-5m", "0s"} {
		if _, err := lastingDecision(approval.VerdictAllow, bad, now); err == nil {
			t.Errorf("--for %s must fail", bad)
		}
	}
}

func TestLiveSessionsDropsEndedSessions(t *testing.T) {
	p := testPaths(t)
	startSession(t, p, "alive", "kitchen", time.Now())
	ended := filepath.Join(p.Sessions(), "ended")
	if err := os.MkdirAll(ended, 0o700); err != nil {
		t.Fatal(err)
	}
	info := `{"id":"ended","profile":"kitchen","pid":1073741824,"started":"2026-10-13T12:00:00Z"}`
	if err := os.WriteFile(filepath.Join(ended, "session.json"), []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
	sessions, err := liveSessions(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].info.ID != "alive" {
		t.Errorf("sessions = %+v", sessions)
	}
	if _, err := os.Stat(ended); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the directory of an ended session stays: %v", err)
	}

	var out bytes.Buffer
	if err := listSessions(sessions, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "alive") || !strings.Contains(out.String(), "/work") || !strings.Contains(out.String(), "claude") {
		t.Errorf("sessions = %q", out.String())
	}
}

func TestDoctorChecksProfilesAndSecretSources(t *testing.T) {
	p := testPaths(t)
	t.Setenv("DORIATH_BWRAP", filepath.Join(p.Home, "no-bwrap"))
	writeProfile(t, p, "app", `modules = []

[secrets.private]
keyring = true
`)
	writeProfile(t, p, "broken", `modules = ["no-such-module"]`)

	var out bytes.Buffer
	if code := cmdDoctor(nil, &out); code != 1 {
		t.Errorf("doctor exits %d with problems", code)
	}
	for _, want := range []string{
		"  ✓ secret app/private (keyring)\n",
		"  ✓ profile app\n",
		"  ✕ profile broken: ",
		"  · secrets: run `doriath doctor --secrets`",
		"  · desktop notifications: unavailable",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("doctor lacks %q:\n%s", want, out.String())
		}
	}
}

func TestDoctorSaysHowToFixOAuthAndCommandSecrets(t *testing.T) {
	p := testPaths(t)
	t.Setenv("DORIATH_BWRAP", filepath.Join(p.Home, "no-bwrap"))
	writeProfile(t, p, "app", `modules = []

[secrets.linear.oauth]
mcp = "https://mcp.linear.app/mcp"

[secrets.token]
command = ["no-such-password-manager", "get", "token"]

[secrets.deploy]
command = ["no-such-password-manager", "get", "deploy"]
required = true
`)
	var out bytes.Buffer
	cmdDoctor(nil, &out)
	for _, want := range []string{
		"  · secret app/linear (oauth): not signed in: run `doriath profiles login app linear`: sessions start without it\n",
		"  · secret app/token (command no-such-password-manager): ",
		"  ✕ secret app/deploy (command no-such-password-manager): ",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("doctor lacks %q:\n%s", want, out.String())
		}
	}
}

func TestCompletionZsh(t *testing.T) {
	var out bytes.Buffer
	if err := cmdCompletion([]string{"zsh"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := cmdCompletion([]string{"fish"}, &out); err == nil {
		t.Error("only zsh has a completion")
	}
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh is not installed")
	}
	cmd := exec.Command(zsh, "-n")
	cmd.Stdin = strings.NewReader(zshCompletion)
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("zsh -n: %v\n%s", err, msg)
	}
}

func TestComplete(t *testing.T) {
	p := testPaths(t)
	writeProfile(t, p, "garden", "")
	writeProfile(t, p, "kitchen", "")
	s := startSession(t, p, "s1", "kitchen", time.Now())
	id, decided := s.submit(t, "Push", "")

	complete := func(what string) string {
		var out bytes.Buffer
		cmdComplete([]string{what}, &out)
		return out.String()
	}
	if got := complete("profiles"); got != "garden\nkitchen\n" {
		t.Errorf("profiles = %q", got)
	}
	if got := complete("sessions"); got != "s1\n" {
		t.Errorf("sessions = %q", got)
	}
	if got := complete("approvals"); got != id+"\n" {
		t.Errorf("approvals = %q", got)
	}
	if err := s.manager.Decide(id, approval.Decision{Verdict: approval.VerdictDeny}); err != nil {
		t.Fatal(err)
	}
	receive(t, decided)
}

func TestCleanCaches(t *testing.T) {
	p := testPaths(t)
	writeProfile(t, p, "kitchen", "")
	cache := filepath.Join(p.AgentCache("kitchen"), "go")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := cmdProfiles([]string{"clean", "missing"}, strings.NewReader(""), &out); err == nil {
		t.Error("clean of an unknown profile must fail")
	}
	startSession(t, p, "s1", "kitchen", time.Now())
	if err := cmdProfiles([]string{"clean", "kitchen"}, strings.NewReader(""), &out); err == nil || !strings.Contains(err.Error(), "is running") {
		t.Errorf("clean while a session runs = %v", err)
	}
	if err := os.RemoveAll(filepath.Join(p.Sessions(), "s1")); err != nil {
		t.Fatal(err)
	}
	if err := cmdProfiles([]string{"clean", "kitchen"}, strings.NewReader(""), &out); err != nil || out.String() != "Removed the caches of profile kitchen.\n" {
		t.Fatalf("clean = %q, %v", out.String(), err)
	}
	if _, err := os.Stat(p.AgentCache("kitchen")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the cache stays: %v", err)
	}
}

func TestPickSession(t *testing.T) {
	sessions := []liveSession{{info: session.Info{ID: "a"}}, {info: session.Info{ID: "b"}}}
	retry := func(id string) string { return "doriath exec --session " + id }
	if dir, err := pickSession(sessions, "b", "/run", retry); err != nil || dir != "/run/b" {
		t.Errorf("named = %q, %v", dir, err)
	}
	if _, err := pickSession(sessions, "c", "/run", retry); err == nil {
		t.Error("an unknown session must fail")
	}
	if _, err := pickSession(sessions, "", "/run", retry); err == nil || !strings.Contains(err.Error(), "doriath exec --session a") || !strings.Contains(err.Error(), "doriath exec --session b") {
		t.Errorf("several = %v", err)
	}
	if dir, err := pickSession(sessions[:1], "", "/run", retry); err != nil || dir != "/run/a" {
		t.Errorf("only one = %q, %v", dir, err)
	}
	if _, err := pickSession(nil, "", "/run", retry); err == nil {
		t.Error("no sessions must fail")
	}
}

func TestRunRefusesRoot(t *testing.T) {
	if err := refuseRoot(0); err == nil || !strings.Contains(err.Error(), "root") {
		t.Errorf("root: %v", err)
	}
	if err := refuseRoot(1000); err != nil {
		t.Errorf("a user: %v", err)
	}
}

func TestStartDirs(t *testing.T) {
	project := t.TempDir()
	sub := filepath.Join(project, "pkg")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ current, cwd, wantCurrent, wantCwd string }{
		{"", sub, sub, sub},
		{project, sub, project, sub},
		{project, "/elsewhere", project, project},
	} {
		current, cwd, err := startDirs(tc.current, tc.cwd)
		if err != nil || current != tc.wantCurrent || cwd != tc.wantCwd {
			t.Errorf("startDirs(%q, %q) = %q, %q, %v", tc.current, tc.cwd, current, cwd, err)
		}
	}
	if _, _, err := startDirs(filepath.Join(project, "missing"), sub); err == nil {
		t.Error("a missing --current must fail")
	}
}

func TestLoginArguments(t *testing.T) {
	p := testPaths(t)
	writeProfile(t, p, "plain", `modules = []`)
	var out bytes.Buffer
	login := func(args ...string) error {
		return cmdProfiles(append([]string{"login"}, args...), strings.NewReader(""), &out)
	}
	if err := login(); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Errorf("without a profile: %v", err)
	}
	if err := login("plain"); err != nil || !strings.Contains(out.String(), "Nothing to sign in to") {
		t.Errorf("a profile without OAuth secrets: %q, %v", out.String(), err)
	}
	if err := login("plain", "linear"); err == nil || !strings.Contains(err.Error(), "[secrets.linear]") {
		t.Errorf("an unknown secret: %v", err)
	}
	if err := login("plain", "linear", "notion"); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Errorf("two secrets: %v", err)
	}
}

func TestLoginSkipsSecretsAlreadySignedIn(t *testing.T) {
	p := testPaths(t)
	writeProfile(t, p, "app", `modules = []

[secrets.linear.oauth]
mcp = "https://mcp.linear.app/mcp"

[secrets.notion.oauth]
mcp = "https://mcp.notion.com/mcp"

[secrets.key]
command = ["true"]
`)
	for _, s := range []string{"linear", "notion"} {
		state := oauth.StatePath(p.State, "app", s)
		if err := os.MkdirAll(filepath.Dir(state), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(state, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := cmdProfiles([]string{"login", "app"}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	want := "Already signed in for linear; name it to sign in again.\n" +
		"Already signed in for notion; name it to sign in again.\n" +
		"Nothing to sign in to in profile app.\n"
	if out.String() != want {
		t.Errorf("login = %q, want %q", out.String(), want)
	}
	if err := cmdProfiles([]string{"login", "app", "key"}, strings.NewReader(""), &out); err == nil || !strings.Contains(err.Error(), "profile app has no [secrets.key] with oauth") {
		t.Errorf("a secret without oauth: %v", err)
	}
}

type memoryKeyring map[string]string

func (m memoryKeyring) Read(profile, name string) (secret.Value, error) {
	v, ok := m[profile+"/"+name]
	if !ok {
		return secret.Value{}, secret.ErrNotInKeyring
	}
	return secret.NewValue([]byte(v)), nil
}

func (m memoryKeyring) Write(profile, name string, v secret.Value) error {
	m[profile+"/"+name] = string(v.Reveal())
	return nil
}

func TestLoginStoresKeyringSecretsThatAreMissing(t *testing.T) {
	p := testPaths(t)
	writeProfile(t, p, "app", `modules = []

[secrets.forge]
keyring = true

[secrets.stored]
keyring = true
`)
	kr := memoryKeyring{"app/stored": "old"}
	var out bytes.Buffer
	if err := cmdLogin(p, loader(p, p.Home), []string{"app"}, strings.NewReader("tok\n"), kr, &out); err != nil {
		t.Fatal(err)
	}
	if kr["app/forge"] != "tok" || kr["app/stored"] != "old" {
		t.Errorf("keyring = %v", kr)
	}
	for _, want := range []string{"Stored forge in the keyring for profile app.", "Secret stored is already in the keyring; name it to replace it."} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output %q lacks %q", out.String(), want)
		}
	}
	if err := cmdLogin(p, loader(p, p.Home), []string{"app", "stored"}, strings.NewReader("new\n"), kr, &out); err != nil || kr["app/stored"] != "new" {
		t.Errorf("naming a stored secret replaces it: %v, %v", kr, err)
	}
	if err := cmdLogin(p, loader(p, p.Home), []string{"app", "forge"}, strings.NewReader("\n"), kr, &out); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Errorf("an empty value: %v", err)
	}
}

func TestApprovalsListSkipsASessionThatDoesNotAnswer(t *testing.T) {
	p := testPaths(t)
	s := startSession(t, p, "s1", "kitchen", time.Now())
	id, decided := s.submit(t, "Push", "")
	silent := filepath.Join(p.Sessions(), "s2")
	if err := os.MkdirAll(silent, 0o700); err != nil {
		t.Fatal(err)
	}
	info := `{"id":"s2","profile":"garden","pid":` + strconv.Itoa(os.Getpid()) + `}`
	if err := os.WriteFile(filepath.Join(silent, session.InfoFile), []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := approvals(t, "list")
	if err != nil || !strings.Contains(out, id) {
		t.Errorf("list = %q, %v", out, err)
	}
	if _, err := approvals(t, "deny", id); err != nil {
		t.Fatal(err)
	}
	receive(t, decided)
}

func TestSessionsWithoutSessions(t *testing.T) {
	testPaths(t)
	var out bytes.Buffer
	if err := cmdStatus(nil, &out); err != nil || out.String() != "No running sessions.\n" {
		t.Errorf("sessions = %q, %v", out.String(), err)
	}
}

func TestApprovalsListsTheWarningOfARequest(t *testing.T) {
	var out bytes.Buffer
	now := time.Unix(100, 0)
	req := approval.Request{ID: "r1", Kind: approval.KindPath, Summary: "Let the agent write /tmp", Warning: "/tmp holds the sockets of your desktop.", Expires: now.Add(time.Minute)}
	printPending(&out, []pendingRequest{{Request: req}}, now)
	if !strings.Contains(out.String(), "r1: Warning from doriath: /tmp holds the sockets of your desktop. You can allow it once only.") {
		t.Errorf("out = %q", out.String())
	}
}

func TestAnAnswerTakesItsFlagsBeforeOrAfterTheID(t *testing.T) {
	for _, args := range [][]string{{"ab12c", "--for", "session", "--reason", "use CI"}, {"--for", "session", "--reason", "use CI", "ab12c"}} {
		id, lasting, reason, err := parseAnswer("deny", args)
		if err != nil || id != "ab12c" || lasting != "session" || reason != "use CI" {
			t.Errorf("%v: %q %q %q, %v", args, id, lasting, reason, err)
		}
	}
	for _, args := range [][]string{nil, {"ab12c", "cd34e"}, {"--reason", "x"}} {
		if _, _, _, err := parseAnswer("allow", args); err == nil {
			t.Errorf("%v: no error", args)
		}
	}
}
