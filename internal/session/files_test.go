package session

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/ca"
	"software.sslmate.com/src/go-pkcs12"
)

const desktopGit = "user.name\nTest User\x00user.email\nf@example.org\x00user.signingkey\n/home/u/.ssh/id_ed25519.pub\x00" +
	"credential.helper\n/usr/lib/git-core/git-credential-libsecret\x00url.ssh://git@github.com/acme/.insteadof\nhttps://github.com/acme/\x00" +
	"include.path\n/home/u/.local/gitconfig\x00core.fsmonitor\nrm -rf /\x00push.autosetupremote\ntrue\x00alias.lg\nlog --graph \"--format=%h\"\x00"

func TestGitConfigWithRealGit(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	data := GitConfig(GitOptions{SigningKey: "/run/doriath/signing.pub", RewriteSSH: []SSHRewrite{{Host: "github.com", User: "git", Port: 22}}, Desktop: []byte(desktopGit)})
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
	data := string(GitConfig(GitOptions{Desktop: []byte(desktopGit)}))
	if !strings.Contains(data, "gpgsign = \"false\"") || strings.Contains(data, "signingkey") {
		t.Errorf("config = %s", data)
	}
}

func TestJJ(t *testing.T) {
	if got := string(JJConfig("/run/doriath/signing.pub")); !strings.Contains(got, `key = "/run/doriath/signing.pub"`) || !strings.Contains(got, `behavior = "own"`) {
		t.Errorf("jj = %s", got)
	}
	kind := func(p string) string {
		if p == "/home/u/.config/jj/config.toml" {
			return "file"
		}
		return ""
	}
	if got := JJConfigPath("/home/u", kind, "/run/doriath/jj.toml"); got != "/home/u/.config/jj/config.toml:/run/doriath/jj.toml" {
		t.Errorf("path = %s", got)
	}
}

func TestCABundle(t *testing.T) {
	read := func(p string) ([]byte, error) {
		if p == "/etc/ssl/cert.pem" {
			return []byte("SYSTEM\n\n"), nil
		}
		return nil, fs.ErrNotExist
	}
	got, err := CABundle(func(string) string { return "" }, read, []byte("SESSION\n"))
	if err != nil || string(got) != "SYSTEM\nSESSION\n" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := CABundle(func(string) string { return "" }, func(string) ([]byte, error) { return nil, fs.ErrNotExist }, nil); err == nil {
		t.Fatal("want error")
	}
}

func TestJavaTrustStoreHoldsTheBundle(t *testing.T) {
	authority, err := ca.New([]string{"github.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	store, err := JavaTrustStore(append([]byte("not a certificate\n"), authority.CertPEM()...))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := pkcs12.DecodeTrustStore(store, JavaTrustStorePassword)
	if err != nil || len(certs) != 1 || !certs[0].IsCA {
		t.Fatalf("trust store = %v, %v", certs, err)
	}
	if _, err := JavaTrustStore([]byte("nothing")); err == nil {
		t.Error("an empty trust store would make Java trust nothing")
	}
}

func TestGitConfigRewritesSSHWithItsUserAndPort(t *testing.T) {
	data := string(GitConfig(GitOptions{RewriteSSH: []SSHRewrite{{Host: "git.example.org", User: "forgejo", Port: 2222}}}))
	for _, want := range []string{"forgejo@git.example.org:", "ssh://forgejo@git.example.org/", "ssh://forgejo@git.example.org:2222/"} {
		if !strings.Contains(data, want) {
			t.Errorf("gitconfig lacks %q:\n%s", want, data)
		}
	}
}
