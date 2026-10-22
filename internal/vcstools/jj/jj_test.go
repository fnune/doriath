package jj

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/vcstools"
)

func osKind(p string) string {
	info, err := os.Stat(p)
	switch {
	case err != nil:
		return ""
	case info.IsDir():
		return "dir"
	}
	return "file"
}

func home(t *testing.T, files map[string]string) string {
	t.Helper()
	h := t.TempDir()
	for name, content := range files {
		p := filepath.Join(h, ".config", "jj", name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func TestTheJailSignsWithTheProfilesKeyOrNotAtAll(t *testing.T) {
	h := home(t, map[string]string{"config.toml": "[user]\nname = \"me\"\n"})
	inJail := func(name string) string { return "/run/doriath/" + name }
	c := New(h, osKind).Jail(vcstools.Jail{SigningKey: "/run/doriath/signing.pub", Path: inJail})
	if got := string(c.Files["jj.toml"]); !strings.Contains(got, `key = "/run/doriath/signing.pub"`) || !strings.Contains(got, `behavior = "own"`) {
		t.Errorf("with a key: %s", got)
	}
	if got := c.Env["JJ_CONFIG"]; got != filepath.Join(h, ".config/jj/config.toml")+":/run/doriath/jj.toml" {
		t.Errorf("JJ_CONFIG = %s", got)
	}
	c = New(h, osKind).Jail(vcstools.Jail{Path: inJail})
	if got := string(c.Files["jj.toml"]); !strings.Contains(got, `behavior = "drop"`) {
		t.Errorf("without a key, jj would sign with a key the jail lacks: %s", got)
	}
}

func TestHostSignsReadsSigningBehavior(t *testing.T) {
	for files, want := range map[string]string{
		"":                                 "",
		"[signing]\nbehavior = \"own\"\n":  "signing.behavior = own",
		"[signing]\nbehavior = \"keep\"\n": "signing.behavior = keep",
		"[signing]\nbehavior = \"drop\"\n": "",
	} {
		if got := New(home(t, map[string]string{"config.toml": files}), osKind).HostSigns(); got != want {
			t.Errorf("%q: HostSigns = %q, want %q", files, got, want)
		}
	}
	later := home(t, map[string]string{"config.toml": "[signing]\nbehavior = \"own\"\n", "conf.d/z.toml": "[signing]\nbehavior = \"drop\"\n"})
	if got := New(later, osKind).HostSigns(); got != "" {
		t.Errorf("a later file that drops signing is ignored: %q", got)
	}
}
