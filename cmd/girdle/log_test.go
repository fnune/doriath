package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func record(t *testing.T, line string) auditRecord {
	t.Helper()
	var r auditRecord
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestLogFilterAndFormat(t *testing.T) {
	denied := record(t, `{"time":"2026-10-13T09:49:34Z","session":"s1","profile":"k","event":"egress","data":{"kind":"denied","host":"pypi.org","reason":"host not in the profile"}}`)
	tunnel := record(t, `{"time":"2026-10-13T09:49:35Z","session":"s2","profile":"k","event":"egress","data":{"kind":"tunnel","host":"example.com"}}`)
	decided := record(t, `{"time":"2026-10-13T09:49:41Z","session":"s1","profile":"k","event":"approval-decided","data":{"request":{"id":"r1","summary":"Create a GitHub release"},"decision":{"verdict":"deny","by":"cli"}}}`)

	only := logFilter{denied: true}
	if !only.keep(denied) || only.keep(tunnel) || !only.keep(decided) {
		t.Error("--denied keeps egress denials and denied approvals only")
	}
	if (logFilter{session: "s2"}).keep(denied) || !(logFilter{session: "s2"}).keep(tunnel) {
		t.Error("--session")
	}
	if (logFilter{since: time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC)}).keep(tunnel) {
		t.Error("--since")
	}
	if got := formatRecord(denied); !strings.Contains(got, "denied pypi.org (host not in the profile)") {
		t.Errorf("denied = %q", got)
	}
	if got := formatRecord(decided); !strings.Contains(got, "deny r1: Create a GitHub release (by cli)") {
		t.Errorf("decided = %q", got)
	}
}
