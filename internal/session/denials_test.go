package session

import (
	"testing"

	"github.com/fnune/doriath/internal/proxy"
)

type eventList []proxy.Event

func (l *eventList) Egress(e proxy.Event) { *l = append(*l, e) }

func TestEgressLogCollapsesRepeats(t *testing.T) {
	var events eventList
	l := newEgressLog(&events)
	for range 5 {
		l.Egress(proxy.Event{Kind: "denied", Host: "mcp.notion.com", Reason: "host not in the profile"})
	}
	l.Egress(proxy.Event{Kind: "denied", Host: "evil.example", Reason: "host not in the profile"})
	l.Egress(proxy.Event{Kind: "tunnel", Host: "example.com"})
	l.Egress(proxy.Event{Kind: "tunnel", Host: "example.com"})
	if len(events) != 4 {
		t.Fatalf("events = %+v", events)
	}
	d := l.Denials()
	if len(d) != 2 || d[0].Host != "mcp.notion.com" || d[0].Count != 5 || d[1].Count != 1 {
		t.Fatalf("denials = %+v", d)
	}
}
