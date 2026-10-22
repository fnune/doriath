package profile

import (
	"strings"
	"testing"
)

func TestEditRulesLoad(t *testing.T) {
	p := mustLoad(t, `
[[mounts]]
path = "{git}/config"
edit = { format = "git-config", safe = ["Branch.*.Remote = *"] }

[[mounts]]
path = "~/notes.md"
edit = { format = "text" }
`, nil)
	if e := p.GitEdits["config"]; e == nil || e.Format != FormatGitConfig || len(e.Safe) != 1 || e.Safe[0].Key != "branch.*.remote" {
		t.Errorf("git edits = %+v", p.GitEdits)
	}
	for _, m := range p.Mounts {
		if m.Path == "{git}/config" {
			t.Error("a git directory's edit rule became a mount")
		}
	}
}

func TestEditRulesThatCannotWork(t *testing.T) {
	for body, want := range map[string]string{
		`path = "{git}/hooks"` + "\nedit = { format = \"text\" }":                                      "names only config",
		`path = "{git}/config"`:                                                                        "add edit",
		`path = "~/notes.md"` + "\nmode = \"write\"\nedit = { format = \"text\" }":                     "read-only files",
		`path = "~/notes.md"` + "\nedit = { format = \"yaml\" }":                                       "want git-config or text",
		`path = "~/notes.md"` + "\nedit = { format = \"text\", safe = [\"a = b\"] }":                   "a text file has none",
		`path = "{git}/config"` + "\nedit = { format = \"git-config\", safe = [\"branch.*.remote\"] }": "want KEY = VALUE",
	} {
		_, err := load(t, "[[mounts]]\n"+body+"\n", nil)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", body, err, want)
		}
	}
}

func TestSigningEitherAKeyOrUnsigned(t *testing.T) {
	if p := mustLoad(t, "[signing]\nenable = false\n", nil); !p.Unsigned {
		t.Error("enable = false is not unsigned")
	}
	if _, err := load(t, "[signing]\nkey = \"k\"\nenable = false\n\n[secrets.k]\nfile = \"/k\"\n", nil); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Errorf("err = %v", err)
	}
}
