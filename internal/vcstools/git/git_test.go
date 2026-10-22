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
	data := config([]byte(desktopGit), vcstools.Jail{SigningKey: "/run/doriath/signing.pub", RewriteSSH: []vcstools.SSHRewrite{{Host: "github.com", User: "git", Port: 22}}})
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
	data := string(config([]byte(desktopGit), vcstools.Jail{}))
	if !strings.Contains(data, "gpgsign = \"false\"") || strings.Contains(data, "signingkey") {
		t.Errorf("config = %s", data)
	}
}

func TestGitConfigRewritesSSHWithItsUserAndPort(t *testing.T) {
	data := string(config(nil, vcstools.Jail{RewriteSSH: []vcstools.SSHRewrite{{Host: "git.example.org", User: "forgejo", Port: 2222}}}))
	for _, want := range []string{"forgejo@git.example.org:", "ssh://forgejo@git.example.org/", "ssh://forgejo@git.example.org:2222/"} {
		if !strings.Contains(data, want) {
			t.Errorf("gitconfig lacks %q:\n%s", want, data)
		}
	}
}

func TestAKeyThatGitWouldNotPrintStaysOut(t *testing.T) {
	got := string(config([]byte("user.name\nMe\x00user.email \nevil@example.com\x00"), vcstools.Jail{}))
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
		if got := New([]byte(desktop)).HostSigns(); got != want {
			t.Errorf("%q: HostSigns = %q, want %q", desktop, got, want)
		}
	}
}
