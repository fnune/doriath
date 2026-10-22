package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/vcstools"
)

const desktopGit = "user.name\nTest User\x00user.email\nf@example.org\x00user.signingkey\n/home/u/.ssh/id_ed25519.pub\x00" +
	"credential.helper\n/usr/lib/git-core/git-credential-libsecret\x00url.ssh://git@github.com/acme/.insteadof\nhttps://github.com/acme/\x00" +
	"include.path\n/home/u/.local/gitconfig\x00core.fsmonitor\nrm -rf /\x00push.autosetupremote\ntrue\x00alias.lg\nlog --graph \"--format=%h\"\x00"

func TestGitConfigWithRealGit(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	data := config([]byte(desktopGit), vcstools.Jail{SigningKey: "/run/doriath/signing.pub", RewriteSSH: []vcstools.SSHRewrite{{Host: "github.com", User: "git", Port: 22}}}, nil)
	path := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	get := func(args ...string) string {
		out, err := exec.Command(gitBin, append([]string{"config", "-f", path}, args...)...).Output()
		if err != nil {
			return "<unset>"
		}
		return strings.TrimSpace(string(out))
	}
	for key, want := range map[string]string{
		"user.name":            "Test User",
		"user.signingkey":      "/run/doriath/signing.pub",
		"gpg.format":           "ssh",
		"commit.gpgsign":       "true",
		"push.autosetupremote": "true",
		"alias.lg":             `log --graph "--format=%h"`,
		"credential.helper":    "",
		"core.fsmonitor":       "<unset>",
		"include.path":         "<unset>",
	} {
		if got := get("--get", key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	rewrites := get("--get-all", "url.https://github.com/.insteadof")
	if !strings.Contains(rewrites, "git@github.com:") || !strings.Contains(rewrites, "ssh://git@github.com/") {
		t.Errorf("rewrites = %q", rewrites)
	}
	if get("--get-all", "url.ssh://git@github.com/acme/.insteadof") != "<unset>" {
		t.Error("desktop SSH rewrites must not reach the jail")
	}
}

func TestGitConfigWithoutSigning(t *testing.T) {
	data := string(config([]byte(desktopGit), vcstools.Jail{}, nil))
	if !strings.Contains(data, "gpgsign = \"false\"") || strings.Contains(data, "signingkey") {
		t.Errorf("config = %s", data)
	}
}

func TestGitConfigRewritesSSHWithItsUserAndPort(t *testing.T) {
	data := string(config(nil, vcstools.Jail{RewriteSSH: []vcstools.SSHRewrite{{Host: "git.example.org", User: "forgejo", Port: 2222}}}, nil))
	for _, want := range []string{"forgejo@git.example.org:", "ssh://forgejo@git.example.org/", "ssh://forgejo@git.example.org:2222/"} {
		if !strings.Contains(data, want) {
			t.Errorf("gitconfig lacks %q:\n%s", want, data)
		}
	}
}

func TestAKeyThatGitWouldNotPrintStaysOut(t *testing.T) {
	got := string(config([]byte("user.name\nMe\x00user.email \nevil@example.com\x00"), vcstools.Jail{}, nil))
	if !strings.Contains(got, "Me") || strings.Contains(got, "evil@example.com") {
		t.Errorf("config:\n%s", got)
	}
}

func TestHostSignsReadsTheSigningSettings(t *testing.T) {
	for desktop, want := range map[string]string{
		"user.name\nMe\x00":                           "",
		"commit.gpgsign\ntrue\x00":                    "commit.gpgsign",
		"tag.gpgSign\nyes\x00":                        "tag.gpgsign",
		"commit.gpgsign\nfalse\x00tag.gpgsign\n0\x00": "",
	} {
		if got := New([]byte(desktop), nil).HostSigns(); got != want {
			t.Errorf("%q: HostSigns = %q, want %q", desktop, got, want)
		}
	}
}

func TestTheJailGetsTheFilesYourGlobalConfigNames(t *testing.T) {
	read := func(p string) ([]byte, error) {
		if p == "/missing" {
			return nil, os.ErrNotExist
		}
		return []byte(p), nil
	}
	none := func(string) string { return "" }
	for desktop, want := range map[string]map[string]string{
		"": {"core.excludesfile": "/home/u/.config/git/ignore", "core.attributesfile": "/home/u/.config/git/attributes"},
		"core.excludesFile\n~/.gitignore\x00commit.template\n/etc/msg\x00core.attributesfile\n/missing\x00": {"core.excludesfile": "/home/u/.gitignore", "commit.template": "/etc/msg"},
	} {
		got := HostFiles([]byte(desktop), "/home/u", none, read)
		if len(got) != len(want) {
			t.Errorf("%q: %q", desktop, got)
		}
		for k, v := range want {
			if string(got[k]) != v {
				t.Errorf("%q: %s = %q, want %s", desktop, k, got[k], v)
			}
		}
	}
	if got := HostFiles(nil, "/home/u", func(string) string { return "/x" }, read); string(got["core.excludesfile"]) != "/x/git/ignore" {
		t.Errorf("with XDG_CONFIG_HOME: %q", got)
	}
	c := New([]byte("core.excludesfile\n/host/only\x00"), map[string][]byte{"core.excludesfile": []byte(".idea/\n")}).Jail(vcstools.Jail{Path: func(n string) string { return "/run/doriath/" + n }})
	if string(c.Files["gitignore"]) != ".idea/\n" {
		t.Errorf("files: %q", c.Files)
	}
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, c.Files[configFile], 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "config", "--file", path, "core.excludesfile").Output(); err != nil || strings.TrimSpace(string(out)) != "/run/doriath/gitignore" {
		t.Errorf("core.excludesfile = %q, %v", out, err)
	}
}
