package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/session"
)

func TestStatusline(t *testing.T) {
	testPaths(t)
	var out bytes.Buffer
	if err := cmdStatusline(&out); err != nil || out.String() != "doriath: no session\n" {
		t.Errorf("without a session = %q, %v", out.String(), err)
	}

	b := startBroker(t)
	st := session.Status{Profile: "kitchen", Hosts: []string{"a.example", "b.example"}, Intercepted: []session.StatusHost{{Host: "github.com"}}}
	b.setStatus(st)
	out.Reset()
	if err := cmdStatusline(&out); err != nil || out.String() != "doriath kitchen · 3 hosts\n" {
		t.Errorf("quiet session = %q, %v", out.String(), err)
	}
	st.Pending = 1
	st.Denied = []session.Denial{{Host: "x"}, {Host: "y"}}
	b.setStatus(st)
	out.Reset()
	if err := cmdStatusline(&out); err != nil || out.String() != "doriath kitchen · 3 hosts · 1 waiting for you · 2 blocked\n" {
		t.Errorf("busy session = %q, %v", out.String(), err)
	}
}

func TestStatusFromHost(t *testing.T) {
	p := testPaths(t)
	var out bytes.Buffer
	if err := cmdStatus(nil, &out); err != nil || out.String() != "No running sessions.\n" {
		t.Errorf("without sessions = %q, %v", out.String(), err)
	}
	out.Reset()
	startSession(t, p, "s1", "kitchen", time.Now().Add(-time.Minute))
	if err := cmdStatus(nil, &out); err != nil || !strings.Contains(out.String(), `doriath profile "kitchen" (session s1)`) {
		t.Errorf("one session = %q, %v", out.String(), err)
	}
	startSession(t, p, "s2", "garden", time.Now())
	out.Reset()
	if err := cmdStatus(nil, &out); err != nil || !strings.Contains(out.String(), "kitchen") || !strings.Contains(out.String(), "garden") || !strings.Contains(out.String(), "doriath status --session ID") {
		t.Errorf("two sessions without an id = %q, %v", out.String(), err)
	}
	out.Reset()
	if err := cmdStatus([]string{"--session", "s2"}, &out); err != nil || !strings.Contains(out.String(), `doriath profile "garden" (session s2)`) {
		t.Errorf("named session = %q, %v", out.String(), err)
	}
}
