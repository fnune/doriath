package session

import (
	"strings"
	"testing"
)

func TestDescribeStatus(t *testing.T) {
	got := (Status{
		Session:  "s1",
		Profile:  "kitchen",
		Writable: []string{"/home/u/app"},
		ReadOnly: []string{"/home/u/notes"},
		Hosts:    []string{"proxy.golang.org"},
		Intercepted: []StatusHost{{
			Host: "api.github.com", Credential: true, Default: "approve",
			Rules: []StatusRule{{Method: "GET", Path: "/**", Action: "allow"}, {Method: "POST", Path: "/graphql", Action: "allow", Summary: "queries"}},
		}},
		Ports:   []int{3000, 5432},
		Signing: true,
		Podman:  true,
		Pending: 2,
		Denied:  []Denial{{Host: "pypi.org", Reason: "host not in the profile", Count: 3}},
	}).Describe()
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
		"To reach a host that is not listed, make the request",
		"`doriath request read PATH --reason TEXT`",
		"Do not ask the user to run commands on their machine.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("status lacks %q:\n%s", want, got)
		}
	}
	bare := Status{Session: "s1", Profile: "k"}.Describe()
	for _, absent := range []string{"Writable", "Local ports", "Blocked", "waiting", "no other network access"} {
		if strings.Contains(bare, absent) {
			t.Errorf("an empty status mentions %q:\n%s", absent, bare)
		}
	}
}
