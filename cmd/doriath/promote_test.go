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
	for _, args := range [][]string{nil, {"write"}, {"wait"}, {"wait", "a", "b"}, {"read"}} {
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
		"pending":           {pending: "s1-r4", want: "approval s1-r4 is pending. The user sees it on the approvals page. To wait for the answer, run: `doriath request wait s1-r4`"},
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

func TestRequestReadSendsTheAbsolutePathAndReason(t *testing.T) {
	b := startBroker(t)
	b.set(approval.Decision{Verdict: approval.VerdictAllow}, nil)
	dir := t.TempDir()
	t.Chdir(dir)
	out, err := request(t, "read", "notes", "--reason", "the design docs")
	if err != nil {
		t.Fatal(err)
	}
	cwd, _ := os.Getwd()
	if len(b.reads) != 1 || b.reads[0].Path != filepath.Join(cwd, "notes") || b.reads[0].Reason != "the design docs" {
		t.Errorf("reads = %+v", b.reads)
	}
	if !strings.Contains(out, "is readable now") {
		t.Errorf("out = %q", out)
	}
}

func TestRequestHostSendsTheHostAndReason(t *testing.T) {
	b := startBroker(t)
	b.set(approval.Decision{Verdict: approval.VerdictAllow}, nil)
	out, err := request(t, "host", "registry.npmjs.org", "--reason", "install the dependencies")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.hosts) != 1 || b.hosts[0].Host != "registry.npmjs.org" || b.hosts[0].Reason != "install the dependencies" {
		t.Errorf("hosts = %+v", b.hosts)
	}
	if !strings.Contains(out, "registry.npmjs.org is reachable now") {
		t.Errorf("out = %q", out)
	}
}

func TestRequestForwardSendsBothPortsAndReason(t *testing.T) {
	b := startBroker(t)
	b.set(approval.Decision{Verdict: approval.VerdictAllow}, nil)
	out, err := request(t, "forward", "8080:4321", "--reason", "preview the docs")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.forwards) != 1 || b.forwards[0] != (session.RequestForwardParams{HostPort: 8080, JailPort: 4321, Reason: "preview the docs"}) {
		t.Errorf("forwards = %+v", b.forwards)
	}
	if !strings.Contains(out, "Port 4321 in the jail is forwarded to localhost:8080") {
		t.Errorf("out = %q", out)
	}
	if _, err := request(t, "forward", "99999"); err == nil {
		t.Error("an out of range port was sent")
	}
}

func TestTheXDGOpenFrontAsksQuietlyAndRefusesWithoutASession(t *testing.T) {
	b := startBroker(t)
	b.set(approval.Decision{Verdict: approval.VerdictAllow}, nil)
	if code := cmdOpenFront([]string{"https://example.com/a"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if len(b.opens) != 1 || b.opens[0].URL != "https://example.com/a" {
		t.Errorf("opens = %+v", b.opens)
	}
	if code := cmdOpenFront([]string{"a", "b"}); code == 0 {
		t.Error("two links opened")
	}
	t.Setenv("DORIATH_BROKER", "")
	if code := cmdOpenFront([]string{"https://example.com/a"}); code == 0 {
		t.Error("the front opened a link outside a session")
	}
}
