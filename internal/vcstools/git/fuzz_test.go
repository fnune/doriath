package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/fnune/doriath/internal/vcstools"
)

func FuzzGitConfig(f *testing.F) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		f.Skip("git not installed")
	}
	f.Add([]byte(desktopGit), true)
	f.Add([]byte("user.name\nx\"]\n[credential]\n\thelper = evil\x00"), false)
	f.Add([]byte("alias.x\n\\\"\r\n[include]\npath=/tmp/x\x00"), true)
	f.Add([]byte("Credential.Helper\nstore\x00URL.ssh://git@x/.insteadOf\nhttps://x/\x00"), false)
	f.Add([]byte("a.b\"c.d\nv\x00includeIf.gitdir:/x/.path\n/tmp/c\x00core.hooksPath\n/tmp/h\x00"), true)
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, desktop []byte, signing bool) {
		key := ""
		if signing {
			key = "/run/doriath/signing.pub"
		}
		path := filepath.Join(dir, "gitconfig")
		if err := os.WriteFile(path, config(desktop, vcstools.Jail{SigningKey: key, RewriteSSH: []vcstools.SSHRewrite{{Host: "github.com", User: "git", Port: 22}}}), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(gitBin, "config", "-f", path, "--list", "-z")
		cmd.Env = []string{"GIT_CONFIG_NOSYSTEM=1", "HOME=" + dir, "GIT_CONFIG_GLOBAL=/dev/null"}
		out, err := cmd.Output()
		if err != nil {
			return
		}
		ours := map[string]bool{
			"credential.helper\n":                                      true,
			"url.https://github.com/.insteadof\ngit@github.com:":       true,
			"url.https://github.com/.insteadof\nssh://git@github.com/": true,
		}
		if signing {
			ours["user.signingkey\n"+key] = true
		}
		for _, e := range parseGitList(out) {
			if !gitAllowed(e.key) && !ours[e.key+"\n"+e.value] {
				t.Fatalf("git reads %s = %q from the jail's config", e.key, e.value)
			}
		}
	})
}
