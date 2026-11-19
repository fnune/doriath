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

	"github.com/fnune/doriath/internal/profile"
)

// TestEscapes runs every script in testdata/escapes inside a real jail. Each
// script tries one way out of the jail and exits 0 when doriath's guard held.
// The header says what it tries and what to expect:
//
//	# threat: one line on what the agent would gain
//	# expect: held | works | gap
//	# setup: live-repo | hooks-repo | jj-repo | store-repo | host-listener | rebinding | hidden | work-repo | repo-profiles
//
// "works" scripts check that something legitimate still works, so the corpus
// cannot pass by refusing everything. "gap" scripts document a known limit
// from the limits on the threat model page of the site: the escape must still succeed, so closing the
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
					t.Fatalf("a documented gap no longer opens: update the limits in site/src/content/docs/threat-model.mdx and this script\nthreat: %s\n%s", h.threat, out)
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
			missingInJJRepositories := []string{"hooks", "info"}
			for _, d := range missingInJJRepositories {
				if err := os.RemoveAll(filepath.Join(repo, ".git", d)); err != nil {
					t.Fatal(err)
				}
			}
			extra += fmt.Sprintf("\n[[mounts]]\npath = %q\nmode = \"write\"\n", repo)
			replacements = append(replacements, "{{LIVE_REPO}}", repo)
		case "hooks-repo":
			repo := filepath.Join(e.home, "hooked")
			if err := os.MkdirAll(filepath.Join(repo, ".githooks"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(repo, ".githooks", "pre-commit"), []byte("#!/bin/sh\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			for _, args := range [][]string{{"init", "-q", "-b", "main"}, {"config", "core.hooksPath", ".githooks"}} {
				cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
				cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null")
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("git %v: %v\n%s", args, err, out)
				}
			}
			extra += fmt.Sprintf("\n[[mounts]]\npath = %q\nmode = \"write\"\n", repo)
			replacements = append(replacements, "{{HOOKS_REPO}}", repo)
		case "jj-repo":
			jj, err := exec.LookPath("jj")
			if err != nil {
				t.Skip("jj not installed")
			}
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(e.home, ".config"))
			repo := filepath.Join(e.home, "jjlive")
			if err := os.MkdirAll(repo, 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(jj, "git", "init", "--colocate", repo)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("jj git init: %v\n%s", err, out)
			}
			extra += fmt.Sprintf("\n[[mounts]]\npath = %q\nmode = \"write\"\n", repo)
			bin, err := filepath.EvalSymlinks(jj)
			if err != nil {
				t.Fatal(err)
			}
			replacements = append(replacements, "{{JJ_REPO}}", repo, "{{JJ_BIN}}", bin)
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
		case "store-repo":
			repo := filepath.Join(e.home, "store")
			if err := os.MkdirAll(repo, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, args := range [][]string{{"init", "-q", "-b", "main"}, {"commit", "-q", "--allow-empty", "-m", "first"}, {"gc", "-q"}} {
				cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
				cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e")
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("git %v: %v\n%s", args, err, out)
				}
			}
			if err := os.MkdirAll(filepath.Join(repo, ".git", "rr-cache"), 0o700); err != nil {
				t.Fatal(err)
			}
			lib := filepath.Join(repo, ".git", "modules", "lib")
			for _, d := range []string{filepath.Join(lib, "hooks"), filepath.Join(lib, "objects"), filepath.Join(lib, "refs")} {
				if err := os.MkdirAll(d, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(lib, "config"), []byte("[core]\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			extra += fmt.Sprintf("\n[[mounts]]\npath = %q\nmode = \"read\"\n\n[vcs]\nstore = true\n", repo)
			replacements = append(replacements, "{{STORE_REPO}}", repo)
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
			extra += fmt.Sprintf("\n[[mounts]]\npath = %q\nmode = \"hide\"\n\n[[mounts]]\npath = %q\nmode = \"hide\"\n\n[[mounts]]\npath = %q\nmode = \"hide\"\n", dir, filepath.Join(e.work, ".env"), filepath.Join(e.work, ".envrc"))
		case "work-repo", "repo-profiles":
			cmd := exec.Command("git", "-C", e.work, "init", "-q", "-b", "main")
			cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git init: %v\n%s", err, out)
			}
			if s == "repo-profiles" {
				dir := filepath.Join(e.work, profile.RepoProfiles)
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "dev.toml"), []byte("[egress]\nallow = [\"dev.example\"]\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			replacements = append(replacements, "{{REPO_PROFILES}}", filepath.Join(e.work, profile.RepoProfiles))
		case "rebinding":
			extra += "\n[[egress.programs]]\nbinaries = [\"curl\"]\nallow = [\"rebinding.example\"]\n"
		default:
			t.Fatalf("unknown setup %q", s)
		}
	}
	return strings.NewReplacer(replacements...).Replace(script), extra
}

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
