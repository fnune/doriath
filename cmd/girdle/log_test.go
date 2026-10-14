package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	deniedLine   = `{"time":"2026-10-13T09:49:34Z","session":"s1","profile":"kitchen","event":"egress","data":{"kind":"denied","host":"pypi.org","reason":"host not in the profile"}}`
	tunnelLine   = `{"time":"2026-10-13T09:49:35Z","session":"s2","profile":"garden","event":"egress","data":{"kind":"tunnel","host":"example.com"}}`
	allowedLine  = `{"time":"2026-10-13T09:49:40Z","session":"s1","profile":"kitchen","event":"approval-decided","data":{"request":{"id":"r1","summary":"Push"},"decision":{"verdict":"allow","by":"desktop"}}}`
	refusedLine  = `{"time":"2026-10-13T09:49:41Z","session":"s1","profile":"kitchen","event":"approval-decided","data":{"request":{"id":"r2","summary":"Create a GitHub release"},"decision":{"verdict":"deny","by":"cli"}}}`
	notJSONLine  = `not a record`
	auditLogTime = "2026-10-13T09:49:45Z"
)

func record(t *testing.T, line string) auditRecord {
	t.Helper()
	var r auditRecord
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func writeAuditLog(t *testing.T, lines ...string) string {
	t.Helper()
	p := testPaths(t)
	if err := os.MkdirAll(filepath.Dir(p.AuditLog()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.AuditLog(), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p.AuditLog()
}

func auditLogClock(t *testing.T) *stepClock {
	t.Helper()
	now, err := time.Parse(time.RFC3339, auditLogTime)
	if err != nil {
		t.Fatal(err)
	}
	return newStepClock(now)
}

func TestLogWithoutAnAuditLog(t *testing.T) {
	testPaths(t)
	var out bytes.Buffer
	if err := cmdLog(context.Background(), nil, realClock{}, &out); err != nil || out.String() != "No audit log yet.\n" {
		t.Errorf("log = %q, %v", out.String(), err)
	}
}

func TestLogFilters(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want []string
	}{
		"everything":   {nil, []string{deniedLine, tunnelLine, allowedLine, refusedLine}},
		"one session":  {[]string{"--session", "s2"}, []string{tunnelLine}},
		"one profile":  {[]string{"--profile", "kitchen"}, []string{deniedLine, allowedLine, refusedLine}},
		"denials":      {[]string{"--denied"}, []string{deniedLine, refusedLine}},
		"recent":       {[]string{"--since", "6s"}, []string{allowedLine, refusedLine}},
		"all together": {[]string{"--session", "s1", "--denied", "--since", "10s"}, []string{refusedLine}},
	} {
		t.Run(name, func(t *testing.T) {
			writeAuditLog(t, deniedLine, tunnelLine, notJSONLine, allowedLine, refusedLine)
			var out bytes.Buffer
			if err := cmdLog(context.Background(), append(tc.args, "--json"), auditLogClock(t), &out); err != nil {
				t.Fatal(err)
			}
			if want := strings.Join(tc.want, "\n") + "\n"; out.String() != want {
				t.Errorf("log %v =\n%s\nwant\n%s", tc.args, out.String(), want)
			}
		})
	}
}

func TestLogPrintsOneLinePerRecord(t *testing.T) {
	writeAuditLog(t, deniedLine, notJSONLine, refusedLine)
	var out bytes.Buffer
	if err := cmdLog(context.Background(), nil, realClock{}, &out); err != nil {
		t.Fatal(err)
	}
	want := formatRecord(record(t, deniedLine)) + "\n" + formatRecord(record(t, refusedLine)) + "\n"
	if out.String() != want {
		t.Errorf("log =\n%s\nwant\n%s", out.String(), want)
	}
}

func TestLogRejectsAnUnknownFlag(t *testing.T) {
	writeAuditLog(t, deniedLine)
	if err := cmdLog(context.Background(), []string{"--host", "pypi.org"}, realClock{}, &bytes.Buffer{}); err == nil {
		t.Error("an unknown flag must fail")
	}
}

func TestLogFollowWaitsForWholeLines(t *testing.T) {
	path := writeAuditLog(t, deniedLine)
	appendLog := func(s string) {
		t.Helper()
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteString(s); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := auditLogClock(t)
	var out bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- cmdLog(ctx, []string{"--follow", "--json"}, c, &out) }()

	tick := c.waiting(t)
	appendLog(tunnelLine[:40])
	tick <- c.now
	tick = c.waiting(t)
	if out.String() != deniedLine+"\n" {
		t.Fatalf("a partial line was printed:\n%s", out.String())
	}
	appendLog(tunnelLine[40:] + "\n")
	tick <- c.now
	c.waiting(t)
	if want := deniedLine + "\n" + tunnelLine + "\n"; out.String() != want {
		t.Errorf("follow =\n%s\nwant\n%s", out.String(), want)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("follow ends with %v", err)
	}
}

func TestFormatRecord(t *testing.T) {
	long := strings.Repeat("x", 50)
	for _, tc := range []struct{ event, data, want string }{
		{
			"egress", `{"kind":"denied","host":"pypi.org","reason":"host not in the profile"}`,
			"denied pypi.org (host not in the profile)",
		},
		{
			"egress", `{"kind":"request","method":"GET","host":"api.github.com","path":"/repos","status":200,"exe":"/usr/bin/gh"}`,
			"request GET api.github.com/repos -> 200 by /usr/bin/gh",
		},
		{"approval-requested", `{"id":"r1","summary":"Push to origin"}`, "asked r1: Push to origin"},
		{
			"approval-decided", `{"request":{"id":"r2","summary":"Create a GitHub release"},"decision":{"verdict":"deny","by":"cli"}}`,
			"deny r2: Create a GitHub release (by cli)",
		},
		{"approval-decided", `{"request":{"id":"r1","summary":"Push"},"decision":{"verdict":"allow"}}`, "allow r1: Push"},
		{
			"session-start", `{"cwd":"/work","command":["claude","--prompt","` + long + `"]}`,
			"started in /work: claude --prompt " + long[:40] + "…",
		},
		{
			"session-start", `{"cwd":"/work","command":["claude","x` + strings.Repeat("é", 40) + `"]}`,
			"started in /work: claude x" + strings.Repeat("é", 39) + "…",
		},
		{"session-end", `{"exit":3}`, "ended with exit code 3"},
		{"new-event", `{"a":1}`, `new-event {"a":1}`},
	} {
		r := auditRecord{Time: time.Date(2026, 10, 13, 9, 49, 34, 0, time.UTC), Session: "s1", Profile: "kitchen", Event: tc.event, Data: json.RawMessage(tc.data)}
		want := r.Time.Local().Format("Jan 02 15:04:05") + "  kitchen    s1       " + tc.want
		if got := formatRecord(r); got != want {
			t.Errorf("%s =\n%q\nwant\n%q", tc.event, got, want)
		}
	}
}
