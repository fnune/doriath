package main

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/session"
)

func request(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := cmdRequest(args, &out)
	return out.String(), err
}

func TestRequestNeedsASession(t *testing.T) {
	t.Setenv("DORIATH_BROKER", "")
	if _, err := request(t, "write", "/tmp"); err == nil || !strings.Contains(err.Error(), "runs inside a doriath session") {
		t.Errorf("outside a session = %v", err)
	}
}

func TestRequestUsage(t *testing.T) {
	startBroker(t)
	for _, args := range [][]string{nil, {"write"}, {"wait"}, {"wait", "a", "b"}, {"read", "/tmp"}} {
		if _, err := request(t, args...); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("request %q = %v", args, err)
		}
	}
}

func TestRequestWriteSendsTheAbsolutePathAndReason(t *testing.T) {
	b := startBroker(t)
	b.set(approval.Decision{Verdict: approval.VerdictAllow}, nil)
	t.Chdir(t.TempDir())
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	out, err := request(t, "write", "build", "--reason", "to cache the build")
	want := filepath.Join(cwd, "build")
	if err != nil || out != want+" is writable now.\n" {
		t.Fatalf("allowed = %q, %v", out, err)
	}
	if sent := b.sentWrites(); len(sent) != 1 || sent[0] != (session.RequestWriteParams{Path: want, Reason: "to cache the build"}) {
		t.Errorf("sent %+v", sent)
	}
}

func TestRequestWriteReportsTheDecision(t *testing.T) {
	for name, tc := range map[string]struct {
		decision approval.Decision
		pending  string
		fail     error
		want     string
	}{
		"denied":            {decision: approval.Decision{Verdict: approval.VerdictDeny}, want: "request: denied"},
		"denied for reason": {decision: approval.Decision{Verdict: approval.VerdictDeny, Reason: "not there"}, want: "request: denied: not there"},
		"expired":           {decision: approval.Decision{Verdict: approval.VerdictNone}, want: "nobody decided before the request expired"},
		"pending":           {pending: "s1-r4", want: "approval s1-r4 is pending. To wait for the answer, run: doriath request wait s1-r4"},
		"broker error":      {fail: errors.New("path is hidden"), want: "path is hidden"},
	} {
		t.Run(name, func(t *testing.T) {
			b := startBroker(t)
			b.set(tc.decision, tc.fail)
			b.setPending(tc.pending)
			out, err := request(t, "write", "/data")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want %q", err, tc.want)
			}
			if out != "" {
				t.Errorf("printed %q on failure", out)
			}
		})
	}
}

func TestRequestWaitReadsWhatTheArgumentNames(t *testing.T) {
	t.Chdir(t.TempDir())
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for arg, want := range map[string]session.WaitParams{
		"s1-r2":       {ID: "s1-r2"},
		"pypi.org":    {Host: "pypi.org"},
		"/srv/data":   {Path: "/srv/data"},
		"build/cache": {Path: filepath.Join(cwd, "build/cache")},
		".env":        {Path: filepath.Join(cwd, ".env")},
	} {
		b := startBroker(t)
		b.set(approval.Decision{Verdict: approval.VerdictAllow}, nil)
		out, err := request(t, "wait", arg)
		if err != nil || out != arg+" is allowed.\n" {
			t.Errorf("wait %s = %q, %v", arg, out, err)
		}
		if sent := b.sentWaits(); len(sent) != 1 || sent[0] != want {
			t.Errorf("wait %s sent %+v, want %+v", arg, sent, want)
		}
	}
}

func TestRequestWaitReportsADenial(t *testing.T) {
	b := startBroker(t)
	b.set(approval.Decision{Verdict: approval.VerdictDeny, Reason: "use the mirror"}, nil)
	if _, err := request(t, "wait", "pypi.org"); err == nil || err.Error() != "request: denied: use the mirror" {
		t.Errorf("denied = %v", err)
	}
}

func grant(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := cmdGrant(args, &out)
	return out.String(), err
}

func TestGrantWriteReachesTheSession(t *testing.T) {
	p := testPaths(t)
	first := startSession(t, p, "s1", "kitchen", time.Now().Add(-time.Minute))
	second := startSession(t, p, "s2", "garden", time.Now())

	if _, err := grant(t, "/srv/data"); err == nil || !strings.Contains(err.Error(), "doriath approvals grant --session s2 /srv/data  # profile garden") {
		t.Errorf("two sessions without --session = %v", err)
	}
	out, err := grant(t, "--session", "s2", "/srv/data")
	if err != nil {
		t.Fatal(err)
	}
	if out != "/srv/data is writable in session s2 until it ends.\nadd it to the profile to keep it\n" {
		t.Errorf("grant = %q", out)
	}
	if got := second.grants(); len(first.grants()) != 0 || len(got) != 1 || got[0] != "/srv/data" {
		t.Errorf("granted s1 %v, s2 %v", first.grants(), got)
	}
}

func TestGrantUsage(t *testing.T) {
	testPaths(t)
	for _, args := range [][]string{nil, {"/a", "/b"}, {"--session", "s1"}} {
		if _, err := grant(t, args...); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("grant %q = %v", args, err)
		}
	}
	if _, err := grant(t, "/srv"); err == nil || !strings.Contains(err.Error(), "no running sessions") {
		t.Errorf("without sessions = %v", err)
	}
}

func TestFlagsParseAfterTheOperandThoughTheFlagPackageStopsThere(t *testing.T) {
	for args, want := range map[string][]string{
		"/p --reason r":      {"/p"},
		"--reason r /p":      {"/p"},
		"/p -- --reason":     {"/p", "--reason"},
		"--reason r -- -a b": {"-a", "b"},
	} {
		flags := flag.NewFlagSet("t", flag.ContinueOnError)
		flags.String("reason", "", "")
		got, err := parseInterspersed(flags, strings.Fields(args))
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%s = %q, %v, want %q", args, got, err, want)
		}
	}
}
