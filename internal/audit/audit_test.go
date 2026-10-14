package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fnune/girdle/internal/approval"
	"github.com/fnune/girdle/internal/containers"
	"github.com/fnune/girdle/internal/proxy"
)

func TestRecords(t *testing.T) {
	var buf bytes.Buffer
	now := func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.FixedZone("CEST", 7200)) }
	l := New(&buf, now, "s1", "project")
	l.Egress(proxy.Event{Kind: "denied", Host: "evil.example"})
	l.Requested(approval.Request{ID: "r1", Summary: "Create a release"})
	l.Decided(approval.Request{ID: "r1"}, approval.Decision{Verdict: approval.VerdictDeny, By: "cli"})
	l.ContainerAPI(containers.Event{Kind: "denied", Path: "/containers/create"})

	var events []string
	sc := bufio.NewScanner(&buf)
	for sc.Scan() {
		var r struct {
			Time    time.Time
			Session string
			Profile string
			Event   string
			Data    json.RawMessage
		}
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		if r.Session != "s1" || r.Profile != "project" || r.Time.Location() != time.UTC {
			t.Errorf("record = %+v", r)
		}
		events = append(events, r.Event)
	}
	if !slices.Equal(events, []string{"egress", "approval-requested", "approval-decided", "containers"}) {
		t.Fatalf("events = %v", events)
	}
}

func TestOpenFileKeepsTheLogPrivateAndAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "audit.jsonl")
	for _, line := range []string{"one\n", "two\n"} {
		f, err := OpenFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(line); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "one\ntwo\n" {
		t.Fatalf("log = %q, %v", data, err)
	}
	for p, want := range map[string]os.FileMode{path: 0o600, filepath.Dir(path): 0o700} {
		if info, err := os.Stat(p); err != nil || info.Mode().Perm() != want {
			t.Errorf("%s: mode %v, %v; want %v", p, info.Mode().Perm(), err, want)
		}
	}
}

func TestUnencodableDataStillLeavesARecord(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, time.Now, "s1", "p").Write("custom", func() {})
	var r struct{ Event, Data string }
	if err := json.Unmarshal(buf.Bytes(), &r); err != nil || r.Event != "audit-error" || !strings.Contains(r.Data, "unsupported type") {
		t.Fatalf("record %q: %+v, %v", buf.String(), r, err)
	}
}
