package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

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
