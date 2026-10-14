package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fnune/girdle/internal/approval"
	"github.com/fnune/girdle/internal/profile"
	"github.com/fnune/girdle/internal/session"
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
modules = ["base", "go"]
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
modules = ["base"]

[egress]
allow = ["example.com"]
`)
	out, err := profiles(t, "show", "kitchen")
	if err != nil {
		t.Fatal(err)
	}
	var shown profile.Profile
	if err := json.Unmarshal([]byte(out), &shown); err != nil {
		t.Fatalf("show prints JSON: %v\n%s", err, out)
	}
	if shown.Name != "kitchen" || shown.Description != "Kitchen" || len(shown.Egress.Allow) != 1 || shown.Egress.Allow[0] != "example.com" {
		t.Errorf("show = %+v", shown)
	}
	if _, err := profiles(t, "show", "missing"); err == nil {
		t.Error("show of a missing profile must fail")
	}
	if _, err := profiles(t, "nonsense"); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Errorf("unknown subcommand = %v", err)
	}
}

func TestRunExitStatus(t *testing.T) {
	p := testPaths(t)
	writeProfile(t, p, "app", `modules = ["base"]`)
	if code := run([]string{"profiles", "show", "app"}); code != 0 {
		t.Errorf("show of a profile exits %d", code)
	}
	if code := run([]string{"profiles", "show", "missing"}); code != 1 {
		t.Errorf("show of a missing profile exits %d", code)
	}
	if code := run([]string{"run", "--", "true"}); code != 2 {
		t.Errorf("run without --profile exits %d", code)
	}
	if code := run([]string{"no-such-command"}); code != 2 {
		t.Errorf("unknown command exits %d", code)
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

	writeProfile(t, p, "broken", `modules = ["base"]`)
	t.Setenv("EDITOR", `sed -i 's/base/bsae/'`)
	out.Reset()
	err := cmdProfiles([]string{"edit", "broken"}, strings.NewReader("n\n"), &out)
	if err == nil || !strings.Contains(out.String(), "Edit again?") {
		t.Fatalf("an invalid edit must ask and then fail: %v\n%s", err, out.String())
	}
}

func approvals(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := cmdApprovals(args, strings.NewReader(""), &out)
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
	if d := receive(t, drop); d.Verdict != approval.VerdictDeny || d.Reason != "not today" || d.By != "cli" {
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
	d, err := allowDecision("30m", now)
	if err != nil || d.Lasting != approval.LastingUntil || !d.Until.Equal(now.Add(30*time.Minute)) {
		t.Errorf("30m = %+v, %v", d, err)
	}
	for _, bad := range []string{"forever", "profile", "-5m", "0s"} {
		if _, err := allowDecision(bad, now); err == nil {
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
	if err := cmdSessions(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "alive") || !strings.Contains(out.String(), "/work") || !strings.Contains(out.String(), "claude") {
		t.Errorf("sessions = %q", out.String())
	}
}

func TestDoctorFlagsReadableSecretFile(t *testing.T) {
	p := testPaths(t)
	t.Setenv("GIRDLE_BWRAP", filepath.Join(p.Home, "no-bwrap"))
	keys := filepath.Join(p.Home, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	open := filepath.Join(keys, "open")
	private := filepath.Join(keys, "private")
	if err := os.WriteFile(open, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(private, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeProfile(t, p, "app", `modules = ["base"]

[secrets.open]
file = "`+open+`"

[secrets.private]
file = "`+private+`"
`)
	writeProfile(t, p, "broken", `modules = ["no-such-module"]`)

	var out bytes.Buffer
	if code := cmdDoctor(nil, &out); code != 1 {
		t.Errorf("doctor exits %d with problems", code)
	}
	for _, want := range []string{
		"problem  secret app/open (file): " + open + " is readable by other users: run chmod 600 on it\n",
		"ok       secret app/private (file)\n",
		"ok       profile app\n",
		"problem  profile broken: ",
		"note     secrets: run girdle doctor --secrets",
		"note     desktop notifications: unavailable",
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

func TestClean(t *testing.T) {
	p := testPaths(t)
	writeProfile(t, p, "kitchen", "")
	cache := filepath.Join(p.AgentCache("kitchen"), "go")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := cmdClean([]string{"--caches", "missing"}, strings.NewReader(""), &out); err == nil {
		t.Error("clean of an unknown profile must fail")
	}
	startSession(t, p, "s1", "kitchen", time.Now())
	if err := cmdClean([]string{"--caches", "kitchen"}, strings.NewReader(""), &out); err == nil || !strings.Contains(err.Error(), "is running") {
		t.Errorf("clean while a session runs = %v", err)
	}
	if err := os.RemoveAll(filepath.Join(p.Sessions(), "s1")); err != nil {
		t.Fatal(err)
	}
	if err := cmdClean([]string{"--caches", "kitchen"}, strings.NewReader(""), &out); err != nil || out.String() != "Removed the caches of profile kitchen.\n" {
		t.Fatalf("clean = %q, %v", out.String(), err)
	}
	if _, err := os.Stat(p.AgentCache("kitchen")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the cache stays: %v", err)
	}
}

func TestPickSession(t *testing.T) {
	sessions := []liveSession{{info: session.Info{ID: "a"}}, {info: session.Info{ID: "b"}}}
	if dir, err := pickSession(sessions, "b", "/run"); err != nil || dir != "/run/b" {
		t.Errorf("named = %q, %v", dir, err)
	}
	if _, err := pickSession(sessions, "c", "/run"); err == nil {
		t.Error("an unknown session must fail")
	}
	if _, err := pickSession(sessions, "", "/run"); err == nil || !strings.Contains(err.Error(), "a, b") {
		t.Errorf("several = %v", err)
	}
	if dir, err := pickSession(sessions[:1], "", "/run"); err != nil || dir != "/run/a" {
		t.Errorf("only one = %q, %v", dir, err)
	}
	if _, err := pickSession(nil, "", "/run"); err == nil {
		t.Error("no sessions must fail")
	}
}

func TestParseForward(t *testing.T) {
	for in, want := range map[string][2]int{"3000": {3000, 3000}, "8080:3000": {8080, 3000}} {
		host, jail, err := parseForward(in)
		if err != nil || host != want[0] || jail != want[1] {
			t.Errorf("%s = %d:%d, %v", in, host, jail, err)
		}
	}
	for _, bad := range []string{"", "x", "0", "70000", "80:", "80:x"} {
		if _, _, err := parseForward(bad); err == nil {
			t.Errorf("%q must fail", bad)
		}
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
	writeProfile(t, p, "plain", `modules = ["base"]`)
	var out bytes.Buffer
	if err := cmdLogin(nil, &out); err == nil || !strings.Contains(err.Error(), "--profile") {
		t.Errorf("without --profile: %v", err)
	}
	if err := cmdLogin([]string{"--profile", "plain"}, &out); err != nil || !strings.Contains(out.String(), "Nothing to sign in to") {
		t.Errorf("a profile without OAuth secrets: %q, %v", out.String(), err)
	}
	if err := cmdLogin([]string{"--profile", "plain", "linear"}, &out); err == nil || !strings.Contains(err.Error(), "[secrets.linear]") {
		t.Errorf("an unknown secret: %v", err)
	}
}
