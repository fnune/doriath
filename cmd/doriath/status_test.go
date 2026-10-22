package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/session"
)

func TestDescribeStatus(t *testing.T) {
	got := describeStatus(session.Status{
		Session:  "s1",
		Profile:  "kitchen",
		Writable: []string{"/home/u/app"},
		ReadOnly: []string{"/home/u/notes"},
		Hosts:    []string{"proxy.golang.org"},
		Intercepted: []session.StatusHost{{
			Host: "api.github.com", Credential: true, Default: "approve",
			Rules: []session.StatusRule{{Method: "GET", Path: "/**", Action: "allow"}, {Method: "POST", Path: "/graphql", Action: "allow", Summary: "queries"}},
		}},
		Ports:   []int{3000, 5432},
		Signing: true,
		Podman:  true,
		Pending: 2,
		Denied:  []session.Denial{{Host: "pypi.org", Reason: "host not in the profile", Count: 3}},
	})
	for _, want := range []string{
		"This session runs in doriath profile \"kitchen\" (session s1).\n",
		"Writable paths:\n  - /home/u/app\n",
		"Read-only paths:\n  - /home/u/notes\n",
		"Reachable hosts (HTTPS through the proxy):\n  - proxy.golang.org\n",
		"Host api.github.com (default approve, with a credential the proxy adds):\n  - GET /**: allow\n  - POST /graphql: allow (queries)\n",
		"Local ports: 3000, 5432\n",
		"Commits are signed by an agent key",
		"Containers: podman",
		"Requests waiting for the user: 2\n",
		"Blocked so far:\n  - pypi.org: host not in the profile (3 times)\n",
		"Do not look for another way around a block.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("status lacks %q:\n%s", want, got)
		}
	}
	bare := describeStatus(session.Status{Session: "s1", Profile: "k"})
	for _, absent := range []string{"Writable", "Local ports", "Blocked", "waiting"} {
		if strings.Contains(bare, absent) {
			t.Errorf("an empty status mentions %q:\n%s", absent, bare)
		}
	}
}

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
	if err := cmdStatus(nil, &out); err == nil || !strings.Contains(err.Error(), "no running session") {
		t.Errorf("without sessions = %v", err)
	}
	startSession(t, p, "s1", "kitchen", time.Now().Add(-time.Minute))
	if err := cmdStatus(nil, &out); err != nil || !strings.Contains(out.String(), `doriath profile "kitchen" (session s1)`) {
		t.Errorf("one session = %q, %v", out.String(), err)
	}
	startSession(t, p, "s2", "garden", time.Now())
	if err := cmdStatus(nil, &out); err == nil || !strings.Contains(err.Error(), "several sessions") {
		t.Errorf("two sessions without an id = %v", err)
	}
	out.Reset()
	if err := cmdStatus([]string{"s2"}, &out); err != nil || !strings.Contains(out.String(), `doriath profile "garden" (session s2)`) {
		t.Errorf("named session = %q, %v", out.String(), err)
	}
}
