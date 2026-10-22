package main

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/notify"
)

func TestRunExitStatus(t *testing.T) {
	p := testPaths(t)
	writeProfile(t, p, "app", `modules = ["base"]`)
	for _, tc := range []struct {
		args []string
		want int
	}{
		{nil, 2},
		{[]string{"no-such-command"}, 2},
		{[]string{"help"}, 0},
		{[]string{"version"}, 0},
		{[]string{"profiles", "show", "app"}, 0},
		{[]string{"profiles", "show", "missing"}, 1},
		{[]string{"run", "--", "true"}, 2},
		{[]string{"run", "--profile", "app"}, 2},
		{[]string{"run", "--no-such-flag"}, 2},
		{[]string{"run", "--profile", "app", "--current", "/no/such/dir", "--", "true"}, 2},
		{[]string{"run", "--profile", "missing", "--", "true"}, 1},
		{[]string{"exec", "--no-such-flag"}, 2},
		{[]string{"exec"}, 1},
		{[]string{"doctor", "--no-such-flag"}, 2},
	} {
		if code := run(tc.args); code != tc.want {
			t.Errorf("doriath %q exits %d, want %d", tc.args, code, tc.want)
		}
	}
}

type desktopNotifier struct{}

func (desktopNotifier) Notify(context.Context, approval.Request, func(approval.Decision)) (func(), error) {
	return func() {}, nil
}

func TestHostWaitHoldsRequestsOnlyWhereSomeoneSeesThem(t *testing.T) {
	five := 5 * time.Second
	for name, tc := range map[string]struct {
		approvals config.Approvals
		notifier  approval.Notifier
		want      time.Duration
	}{
		"no notifications":             {config.Approvals{Desktop: true}, notify.None{}, 0},
		"no notifications, configured": {config.Approvals{HostWait: &five}, notify.None{}, five},
		"desktop notifications":        {config.Approvals{Desktop: true}, desktopNotifier{}, 2 * time.Minute},
		"desktop, configured":          {config.Approvals{Desktop: true, HostWait: &five}, desktopNotifier{}, five},
	} {
		if got := hostWait(tc.approvals, tc.notifier); got != tc.want {
			t.Errorf("%s: host wait = %v, want %v", name, got, tc.want)
		}
	}
}

func TestLimitedBufferKeepsTheStartOfLongOutput(t *testing.T) {
	var l limitedBuffer
	start := bytes.Repeat([]byte("a"), 4000)
	for _, chunk := range [][]byte{start, bytes.Repeat([]byte("b"), 200), bytes.Repeat([]byte("c"), 5000)} {
		if n, err := l.Write(chunk); n != len(chunk) || err != nil {
			t.Fatalf("write = %d, %v; the command must not see a short write", n, err)
		}
	}
	want := slices.Concat(start, bytes.Repeat([]byte("b"), 96))
	if !bytes.Equal(l.b, want) {
		t.Errorf("kept %d bytes ending in %q", len(l.b), l.b[len(l.b)-4:])
	}
}
