package jailinit

import (
	"errors"
	"slices"
	"testing"
)

func TestTheCommandChainStopsBelowTheJailsInitUnderBubblewrap(t *testing.T) {
	proc := map[string]string{
		"/proc/30/cmdline": "curl\x00-sS\x00https://example.com\x00",
		"/proc/30/stat":    "30 (curl) S 20 30 30 0",
		"/proc/20/cmdline": "sh\x00-c\x00curl https://example.com\x00",
		"/proc/20/stat":    "20 (my (odd) sh) S 2 20 20 0",
		"/proc/2/cmdline":  "doriath\x00__init\x00--identify\x003128\x00",
		"/proc/2/stat":     "2 (doriath) S 1 2 2 0",
		"/proc/1/cmdline":  "bwrap\x00--args\x005\x00",
	}
	read := func(path string) ([]byte, error) {
		if v, ok := proc[path]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("gone")
	}
	got := commandChain(read, "/proc", 30, 2)
	want := []string{"curl -sS https://example.com", "sh -c 'curl https://example.com'"}
	if !slices.Equal(got, want) {
		t.Errorf("chain = %q, want %q", got, want)
	}
}

func TestACommandLineKeepsTheBoundsOfItsArguments(t *testing.T) {
	for cmdline, want := range map[string]string{
		"curl\x00-H\x00Content-Type: application/json\x00-d\x00{\"a\":1}\x00": `curl -H 'Content-Type: application/json' -d '{"a":1}'`,
		"echo\x00it's\x00\x00":    `echo 'it'\''s' ''`,
		"go\x00test\x00./...\x00": "go test ./...",
		"":                        "",
	} {
		if got := commandLine([]byte(cmdline)); got != want {
			t.Errorf("%q: %s, want %s", cmdline, got, want)
		}
	}
}
