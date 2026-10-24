package jailinit

import (
	"errors"
	"slices"
	"testing"
)

func TestTheCommandChainWalksUpToTheJailsInit(t *testing.T) {
	proc := map[string]string{
		"/proc/30/cmdline": "curl\x00-sS\x00https://example.com\x00",
		"/proc/30/stat":    "30 (curl) S 20 30 30 0",
		"/proc/20/cmdline": "sh\x00-c\x00curl https://example.com\x00",
		"/proc/20/stat":    "20 (my (odd) sh) S 1 20 20 0",
		"/proc/1/cmdline":  "doriath\x00__init\x00",
	}
	read := func(path string) ([]byte, error) {
		if v, ok := proc[path]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("gone")
	}
	got := commandChain(read, "/proc", 30)
	want := []string{"curl -sS https://example.com", "sh -c curl https://example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("chain = %q, want %q", got, want)
	}
}
