package session

import (
	"context"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/control"
)

func describeVia(broker, text string) error {
	return control.Call(context.Background(), broker, MethodDescribe, DescribeParams{Text: text}, nil)
}

func TestDescribeShowsTheAgentsTextOnOneLine(t *testing.T) {
	s, broker, ctl := brokerSession(t, nil)
	if err := describeVia(broker, "  Fix the\nlogin \u202eredirect  "); err != nil {
		t.Fatal(err)
	}
	want := `Fix the login \u202eredirect`
	var info Info
	if err := control.Call(context.Background(), ctl, MethodInfo, struct{}{}, &info); err != nil {
		t.Fatal(err)
	}
	if info.Description != want {
		t.Errorf("info description = %q, want %q", info.Description, want)
	}
	if got := s.status().Summary(0); !strings.Contains(got, "session s1 “"+want+"”") {
		t.Errorf("bar = %q", got)
	}
	if got := s.status().Describe(); !strings.Contains(got, `You describe this session as "Fix the login \\u202eredirect"`) {
		t.Errorf("status text = %q", got)
	}
	if !strings.Contains(s.audit.String(), `"event":"describe"`) {
		t.Errorf("audit = %s", s.audit.String())
	}
}

func TestDescribeRefusesALongDescription(t *testing.T) {
	_, broker, _ := brokerSession(t, nil)
	err := describeVia(broker, strings.Repeat("a", maxDescription+1))
	if err == nil || !strings.Contains(err.Error(), "use at most 60") {
		t.Fatalf("err = %v", err)
	}
}

func TestDescribeIsRateLimitedSoTheLabelCannotFlicker(t *testing.T) {
	_, broker, _ := brokerSession(t, nil)
	for i := range describeBurst {
		if err := describeVia(broker, "task"); err != nil {
			t.Fatalf("description %d: %v", i, err)
		}
	}
	if err := describeVia(broker, "another"); err == nil || !strings.Contains(err.Error(), "too many descriptions") {
		t.Fatalf("err = %v", err)
	}
}

func TestStatusAsksTheAgentToDescribeItsTask(t *testing.T) {
	s := newTestSession(t, nil)
	if got := s.status().Describe(); !strings.Contains(got, "run `doriath describe TEXT`") {
		t.Errorf("status text = %q", got)
	}
}

type recordingNotifier struct{ got approval.Request }

func (r *recordingNotifier) Notify(_ context.Context, req approval.Request, _ func(approval.Decision)) (func(), error) {
	r.got = req
	return func() {}, nil
}

func TestNotificationsCarryTheSessionDescription(t *testing.T) {
	s := newTestSession(t, nil)
	s.description = "Fix the login redirect"
	next := &recordingNotifier{}
	if _, err := (describedNotifier{next: next, session: s.Session}).Notify(context.Background(), approval.Request{ID: "a1"}, nil); err != nil {
		t.Fatal(err)
	}
	if next.got.SessionDescription != "Fix the login redirect" || next.got.ID != "a1" {
		t.Errorf("request = %+v", next.got)
	}
}
