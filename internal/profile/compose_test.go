package profile

import (
	"strings"
	"testing"
	"testing/fstest"
)

func composed(t *testing.T, profiles map[string]string) *Loader {
	t.Helper()
	fsys := fstest.MapFS{}
	for name, body := range profiles {
		fsys[name+".toml"] = file(body)
	}
	return loader(fsys, fstest.MapFS{
		"base.toml":  file("[egress]\nallow = [\"base.example\"]\n"),
		"cloud.toml": file("[egress]\nallow = [\"cloud.example\"]\n"),
	})
}

func TestASecondProfileAddsItsAccessToTheFirst(t *testing.T) {
	l := composed(t, map[string]string{
		"work": `description = "work"
modules = ["base"]

[[mounts]]
path = "/home/u/work"
mode = "write"

[[mounts]]
path = "/home/u/notes"
mode = "write"

[secrets.github]
command = ["gh", "auth", "token"]
`,
		"deploy": `description = "deploys"
modules = ["base", "cloud"]

[[mounts]]
path = "/home/u/notes"
mode = "read"

[egress]
allow = ["deploy.example"]

[secrets.github]
command = ["gh", "auth", "token"]

[secrets.cloud]
command = ["cloud-token"]
`,
	})
	p, err := l.Load("work+deploy")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "work+deploy" || p.Description != "work; deploys" {
		t.Errorf("name %q, description %q", p.Name, p.Description)
	}
	for _, host := range []string{"base.example", "cloud.example", "deploy.example"} {
		if !p.AllowsHost(host) {
			t.Errorf("%s is not allowed", host)
		}
	}
	modes := map[string]Mode{}
	for _, m := range p.Mounts {
		modes[m.Path] = m.Mode
	}
	if modes["/home/u/work"] != ModeWrite || modes["/home/u/notes"] != ModeRead {
		t.Errorf("mounts = %v: where two profiles give one path, the lesser access holds", modes)
	}
	if p.SecretOwner("github") != "deploy" || p.SecretOwner("cloud") != "deploy" || p.SecretOwner("unknown") != "work+deploy" {
		t.Errorf("owners: github %q, cloud %q", p.SecretOwner("github"), p.SecretOwner("cloud"))
	}
	if src := strings.Join(p.Sources["host deploy.example"], ","); src != "profile deploy" {
		t.Errorf("deploy.example comes from %q", src)
	}
}

func TestProfilesThatDisagreeOnASecretOrAKeyAreRefused(t *testing.T) {
	l := composed(t, map[string]string{
		"a": "[secrets.github]\ncommand = [\"gh\", \"auth\", \"token\"]\n\n[secrets.key-a]\nfile = \"/k/a\"\n\n[signing]\nkey = \"key-a\"\n",
		"b": "[secrets.github]\nfile = \"/k/github\"\n\n[secrets.key-b]\nfile = \"/k/b\"\n\n[signing]\nkey = \"key-b\"\n",
	})
	_, err := l.Load("a+b")
	if err == nil || !strings.Contains(err.Error(), `secret "github": profiles a and b give it different sources`) || !strings.Contains(err.Error(), "profiles a and b sign with different keys") {
		t.Fatalf("err = %v", err)
	}
	if _, err := l.Load("a+a"); err == nil || !strings.Contains(err.Error(), "named twice") {
		t.Errorf("a profile named twice: %v", err)
	}
	if _, err := l.Load("a+"); err == nil {
		t.Error("an empty profile name must be refused")
	}
}
