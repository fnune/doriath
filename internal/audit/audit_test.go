package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/fnune/girdle/internal/approval"
	"github.com/fnune/girdle/internal/proxy"
)

func TestRecords(t *testing.T) {
	var buf bytes.Buffer
	now := func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.FixedZone("CEST", 7200)) }
	l := New(&buf, now, "s1", "project")
	l.Egress(proxy.Event{Kind: "denied", Host: "evil.example"})
	l.Requested(approval.Request{ID: "r1", Summary: "Create a release"})
	l.Decided(approval.Request{ID: "r1"}, approval.Decision{Verdict: approval.VerdictDeny, By: "cli"})

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
	if len(events) != 3 || events[0] != "egress" || events[2] != "approval-decided" {
		t.Fatalf("events = %v", events)
	}
}
