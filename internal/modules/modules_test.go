package modules

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/fnune/girdle/internal/profile"
)

func TestEveryModuleLoads(t *testing.T) {
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if name, ok := strings.CutSuffix(e.Name(), ".toml"); ok {
			names = append(names, `"`+name+`"`)
		}
	}
	body := "modules = [" + strings.Join(names, ", ") + "]\nsecrets = { github = \"gh\" }\n"
	l := &profile.Loader{
		Profiles: fstest.MapFS{"all.toml": {Data: []byte(body)}},
		Modules:  []fs.FS{FS},
		Home:     "/home/u",
	}
	p, err := l.Load("all")
	if err != nil {
		t.Fatal(err)
	}
	gh, ok := p.Intercepted("api.github.com")
	if !ok || gh.Credential == nil || p.SecretName(gh.Credential.Secret) != "gh" {
		t.Fatalf("github module: %+v", gh)
	}
	merge, _ := gh.Decide("PUT", "/repos/a/b/pulls/1/merge", nil)
	if merge.Action != profile.ActionApprove {
		t.Errorf("merges must need approval, got %v", merge.Action)
	}
	view, _ := gh.Decide("GET", "/repos/a/b/releases/1", nil)
	if view.Action != profile.ActionAllow {
		t.Errorf("reading releases must pass, got %v", view.Action)
	}
	if !p.Claude.DisableConnectors || !p.Podman {
		t.Error("claude and podman modules not applied")
	}
}
