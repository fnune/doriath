//go:build integration

package session_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestEscapes runs every script in testdata/escapes inside a real jail. Each
// script tries one way out of the jail and exits 0 when girdle's guard held.
// The header says what it tries and what to expect:
//
//	# threat: one line on what the agent would gain
//	# expect: held | works | gap
//	# setup: live-repo | host-listener | rebinding | hidden
//
// "works" scripts check that something legitimate still works, so the corpus
// cannot pass by refusing everything. "gap" scripts document a known limit
// from docs/security-limits.md: the escape must still succeed, so closing the
// gap fails the test until the docs and the script are updated.
func TestEscapes(t *testing.T) {
	scripts, err := filepath.Glob("testdata/escapes/*.sh")
	if err != nil || len(scripts) == 0 {
		t.Fatalf("no escape scripts: %v", err)
	}
	sort.Strings(scripts)
	for _, path := range scripts {
		t.Run(strings.TrimSuffix(filepath.Base(path), ".sh"), func(t *testing.T) {
			h, err := readEscapeHeader(path)
			if err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			e := newEnv(t)
			e.resolver = escapeResolver{}
			script, extra := e.prepareEscape(t, string(body), h.setup)
			code, out := e.run(e.profile(extra), script, nil)
			switch h.expect {
			case "held", "works":
				if code != 0 || strings.Contains(out, "ESCAPED") {
					t.Fatalf("%s\nthreat: %s\nexit %d:\n%s", h.expect, h.threat, code, out)
				}
			case "gap":
				if code == 0 {
					t.Fatalf("a documented gap no longer opens: update docs/security-limits.md and this script\nthreat: %s\n%s", h.threat, out)
				}
			}
		})
	}
}

type escapeHeader struct {
	threat, expect, setup string
}

func readEscapeHeader(path string) (escapeHeader, error) {
	f, err := os.Open(path)
	if err != nil {
		return escapeHeader{}, err
	}
	defer f.Close()
	var h escapeHeader
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "#") {
			break
		}
		key, value, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(line, "#")), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "threat":
			h.threat = value
		case "expect":
			h.expect = value
		case "setup":
			h.setup = value
		}
	}
	switch {
	case h.threat == "":
		return h, fmt.Errorf("%s: no threat line", path)
	case h.expect != "held" && h.expect != "works" && h.expect != "gap":
		return h, fmt.Errorf("%s: expect must be held, works or gap, not %q", path, h.expect)
	}
	return h, sc.Err()
}

// prepareEscape fills the script's placeholders with things outside the
// jail that it should not reach, and returns profile lines its setup needs.
func (e *env) prepareEscape(t *testing.T, script, setup string) (string, string) {
	t.Helper()
	secretFile := filepath.Join(e.home, "outside-secret.txt")
	if err := os.WriteFile(secretFile, []byte("bait-from-the-host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	replacements := []string{"{{SECRET_FILE}}", secretFile, "{{WORK}}", e.work, "{{HOME}}", e.home}
	var extra string
	for _, s := range strings.Fields(setup) {
		switch s {
		case "live-repo":
			repo := filepath.Join(e.home, "live")
			if err := os.MkdirAll(repo, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, args := range [][]string{{"init", "-q", "-b", "main"}, {"commit", "-q", "--allow-empty", "-m", "first"}} {
				cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
				cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e")
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("git %v: %v\n%s", args, err, out)
				}
			}
			extra += fmt.Sprintf("\n[[mounts]]\npath = %q\nmode = \"write\"\n", repo)
			replacements = append(replacements, "{{LIVE_REPO}}", repo)
		case "host-listener":
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = l.Close() })
			go func() {
				for {
					c, err := l.Accept()
					if err != nil {
						return
					}
					_, _ = c.Write([]byte("host service\n"))
					_ = c.Close()
				}
			}()
			replacements = append(replacements, "{{HOST_PORT}}", fmt.Sprint(l.Addr().(*net.TCPAddr).Port))
		case "hidden":
			dir := filepath.Join(e.work, "hidden-dir")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, f := range []string{filepath.Join(dir, "key"), filepath.Join(e.work, ".env")} {
				if err := os.WriteFile(f, []byte("bait-from-the-host\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			extra += fmt.Sprintf("\n[[mounts]]\npath = %q\nmode = \"hide\"\n\n[[mounts]]\npath = %q\nmode = \"hide\"\n", dir, filepath.Join(e.work, ".env"))
		case "rebinding":
			extra += "\n[[egress.programs]]\nbinaries = [\"curl\"]\nallow = [\"rebinding.example\"]\n"
		default:
			t.Fatalf("unknown setup %q", s)
		}
	}
	return strings.NewReplacer(replacements...).Replace(script), extra
}

// escapeResolver answers like public DNS for the test hosts, and points
// rebinding.example at the cloud metadata address, so the proxy's address
// guard runs as it does outside tests.
type escapeResolver struct{}

func (escapeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	switch host {
	case "example.com", "api.github.com", "github.com", "programs.example", "drafted.example":
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	case "rebinding.example":
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	}
	return nil, errors.New("no such host")
}
