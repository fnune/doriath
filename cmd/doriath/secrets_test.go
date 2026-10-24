package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

func pipeWith(t *testing.T, content string) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(content); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func TestSecretsProvideSendsThePipedValueToTheSession(t *testing.T) {
	p := testPaths(t)
	s := startSession(t, p, "s1", "deploy", time.Now())
	var out bytes.Buffer
	if err := cmdSecrets([]string{"provide", "acme"}, pipeWith(t, "pul-token\n"), &out); err != nil {
		t.Fatal(err)
	}
	if got := s.provided["acme"]; got != "pul-token" {
		t.Errorf("provided %q", got)
	}
	if out.String() != "Session s1 uses this value for secret acme until it ends.\n" || strings.Contains(out.String(), "pul-token") {
		t.Errorf("out = %q", out.String())
	}
}

func TestSecretsProvideUsage(t *testing.T) {
	testPaths(t)
	for _, args := range [][]string{nil, {"set", "x"}, {"provide"}, {"provide", "a", "b"}} {
		if err := cmdSecrets(args, pipeWith(t, ""), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("secrets %q = %v", args, err)
		}
	}
}
