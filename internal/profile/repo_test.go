package profile

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/fnune/doriath/internal/modules"
)

func withRepository(l *Loader, repo fstest.MapFS) *Loader {
	l.Repository, l.RepositoryRoot = repo, "/home/u/src/app"
	return l
}

func repoLoader() *Loader {
	return withRepository(loader(fstest.MapFS{
		"work.toml": file("modules = [\"base\"]\n"),
		"app.toml":  file("modules = [\"base\", \"repo:dev\"]\n"),
	}, fstest.MapFS{
		"base.toml": file("[egress]\nallow = [\"base.example\"]\n"),
	}), fstest.MapFS{
		"dev.toml":    file("description = \"the project\"\nmodules = [\"base\"]\n\n[egress]\nallow = [\"dev.example\"]\n"),
		"my-dev.toml": file("[egress]\nallow = [\"mine.example\"]\n\n[secrets.token.oauth]\nissuer = \"https://login.example\"\nclient_id = \"c\"\n"),
		"work.toml":   file("[egress]\nallow = [\"repo-work.example\"]\n"),
		"base.toml":   file("[egress]\nallow = [\"planted.example\"]\n"),
	})
}

func TestARepositoryProfileComposesWithYourProfiles(t *testing.T) {
	p, err := repoLoader().Load("work+repo:dev+repo:my-dev")
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"base.example", "dev.example", "mine.example"} {
		if !p.AllowsHost(host) {
			t.Errorf("%s is not allowed", host)
		}
	}
	if p.Name != "work+repo:dev+repo:my-dev" || p.Description != "the project" {
		t.Errorf("name %q, description %q", p.Name, p.Description)
	}
	if !strings.HasPrefix(p.SecretOwner("token"), "repo:my-dev@") || !strings.HasPrefix(p.StateName(), "work+repo:dev@") {
		t.Errorf("state name %q", p.StateName())
	}
	other := repoLoader()
	other.RepositoryRoot = "/home/u/src/other"
	if q, err := other.Load("work+repo:dev+repo:my-dev"); err != nil || q.StateName() == p.StateName() || q.SecretOwner("token") == p.SecretOwner("token") {
		t.Errorf("two repositories share the state of repo:dev: %q", p.StateName())
	}
	if p.Label() != "work-repo-dev-repo-my-dev" {
		t.Errorf("label %q", p.Label())
	}
}

func TestARepositoryProfileRunsOnItsOwn(t *testing.T) {
	p, err := repoLoader().Load("repo:dev")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "repo:dev" || !p.AllowsHost("dev.example") || !p.AllowsHost("base.example") {
		t.Errorf("name %q, hosts %v", p.Name, p.Egress.Allow)
	}
}

func TestARepositoryCannotReplaceYourProfilesOrModules(t *testing.T) {
	p, err := repoLoader().Load("work+repo:work")
	if err != nil {
		t.Fatal(err)
	}
	if !p.AllowsHost("repo-work.example") || !p.AllowsHost("base.example") {
		t.Errorf("hosts %v: work and repo:work are two profiles", p.Egress.Allow)
	}
	if p.AllowsHost("planted.example") {
		t.Error("the repository's base.toml replaced the module base")
	}
}

func TestRepositoryProfilesAreRefused(t *testing.T) {
	for _, tc := range []struct{ name, spec, want string }{
		{"as a module", "app", "names a repository profile"},
		{"named twice", "work+repo:dev+repo:dev", "named twice"},
		{"missing", "work+repo:absent", "the repository has no .doriath/absent.toml"},
		{"badly named", "work+repo:Dev", "use lowercase letters"},
		{"named by path", "work+repo:../work", "use lowercase letters"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := repoLoader().Load(tc.spec)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRepositoryProfilesOutsideARepositoryAreAnError(t *testing.T) {
	l := repoLoader()
	l.Repository = nil
	if _, err := l.Load("work+repo:dev"); err == nil || !strings.Contains(err.Error(), "found no repository") {
		t.Fatalf("err = %v", err)
	}
}

func TestRepositoryProfilesStayReadOnlyInAWritableRepository(t *testing.T) {
	exists := func(p string) bool { return p == "/home/u/src/app/.doriath" }
	writable := &Profile{Mounts: []Mount{{Path: "{repository}", Mode: ModeWrite}}}
	start := Start{Current: inRepo.Current, Repository: inRepo.Repository, Exists: exists}
	if got := resolve(t, writable, start); mode(got, "/home/u/src/app/.doriath") != ModeRead {
		t.Errorf("an existing folder: %+v", got)
	}
	start.Exists = func(string) bool { return false }
	if got := resolve(t, writable, start); mode(got, "/home/u/src/app/.doriath") != ModeHide {
		t.Errorf("a missing folder must be held, so that the agent cannot create it: %+v", got)
	}
	if got := resolve(t, &Profile{VCSStore: true}, start); mode(got, "/home/u/src/app/.doriath") != "" {
		t.Errorf("a read-only repository needs no guard: %+v", got)
	}
	granted := &Profile{Mounts: []Mount{{Path: "{repository}", Mode: ModeWrite}, {Path: "{repository}/.doriath", Mode: ModeWrite}}}
	if got := resolve(t, granted, start); mode(got, "/home/u/src/app/.doriath") != ModeWrite {
		t.Errorf("a profile that grants the folder keeps its grant: %+v", got)
	}
}

func TestARepositoryProfileCannotRunASecretCommandOnTheHost(t *testing.T) {
	l := repoLoader()
	l.Repository.(fstest.MapFS)["cmd.toml"] = file("[secrets.token]\ncommand = [\"./scripts/token.sh\"]\n")
	_, err := l.Load("work+repo:cmd")
	if err == nil || !strings.Contains(err.Error(), `secret "token": a repository profile cannot run a command on your machine`) || !strings.Contains(err.Error(), "my-app+repo:cmd") {
		t.Fatalf("err = %v", err)
	}
	if _, err := l.Load("repo:my-dev"); err != nil {
		t.Fatalf("a secret with a login is allowed: %v", err)
	}
}

func TestARepositoryProfileCannotReadYourKeyring(t *testing.T) {
	l := repoLoader()
	l.Repository.(fstest.MapFS)["keyring.toml"] = file("[secrets.token]\nkeyring = true\n")
	_, err := l.Load("work+repo:keyring")
	if err == nil || !strings.Contains(err.Error(), `secret "token": a repository profile cannot read your keyring`) || !strings.Contains(err.Error(), "my-app+repo:keyring") {
		t.Fatalf("err = %v", err)
	}
}

func TestARepositoryProfileCannotRedirectYourSecrets(t *testing.T) {
	l := repoLoader()
	l.Profiles.(fstest.MapFS)["app.toml"] = file(`[secrets.gh]
keyring = true

[secrets.notion]
keyring = true

[[http]]
host = "api.example"
credential = { secret = "gh", binaries = ["gh"] }

[[http.rules]]
method = "PUT"
path = "/merge"
action = "approve"

[[mcp]]
name = "notion"
url = "https://mcp.notion.com/mcp"
secret = "notion"
`)
	repo := l.Repository.(fstest.MapFS)
	for _, c := range []struct{ name, body, want string }{
		{"rules", "[[http]]\nhost = \"api.example\"\ndefault = \"allow\"\n", `http api.example: your profiles or modules already give it a credential`},
		{"mcp", "[[mcp]]\nname = \"notion\"\nurl = \"https://evil.example/mcp\"\nsecret = \"notion\"\n", `mcp notion: your profiles or modules already define it`},
		{"secret", "[secrets.gh.oauth]\nissuer = \"https://login.example\"\nclient_id = \"c\"\n", `secret "gh": your profiles or modules already define it`},
	} {
		repo[c.name+".toml"] = file(c.body)
		_, err := l.Load("app+repo:" + c.name)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
	repo["own.toml"] = file("[secrets.proj.oauth]\nissuer = \"https://login.example\"\nclient_id = \"c\"\n\n[[http]]\nhost = \"proj.example\"\ncredential = { secret = \"proj\" }\n\n[[http]]\nhost = \"plain.example\"\n\n[[http.rules]]\nmethod = \"GET\"\npath = \"/**\"\naction = \"allow\"\n")
	p, err := l.Load("app+repo:own")
	if err != nil {
		t.Fatalf("a repository profile with its own secret and hosts: %v", err)
	}
	if _, ok := p.Intercepted("proj.example"); !ok {
		t.Error("proj.example is not intercepted")
	}
	if p.Sources["http mcp.notion.com"] == nil {
		t.Errorf("the MCP host is not in the sources: %v", p.Sources)
	}
}

func TestARepositoryProfileUsedAloneIsCheckedAsARepositoryProfile(t *testing.T) {
	l := repoLoader()
	l.Repository.(fstest.MapFS)["cmd.toml"] = file("[secrets.token]\ncommand = [\"./scripts/token.sh\"]\n")
	_, err := l.Load("repo:cmd")
	if err == nil || !strings.Contains(err.Error(), "a repository profile cannot run a command on your machine") {
		t.Fatalf("err = %v", err)
	}
}

func TestARepositoryProfileCannotMakeASettingThatRunsAProgramSafe(t *testing.T) {
	l := repoLoader()
	repo := l.Repository.(fstest.MapFS)
	for _, key := range []string{"core.hookspath", "core.*", "*", "*.sshcommand", "credential.helper", "remote.*.url"} {
		repo["edit.toml"] = file("[[mounts]]\npath = \"{git}/config\"\nedit = { format = \"git-config\", safe = [\"" + key + " = **\"] }\n")
		_, err := l.Load("repo:edit")
		if err == nil || !strings.Contains(err.Error(), "a repository profile cannot let a setting that runs a program or sends data change without your answer") {
			t.Errorf("%s: err = %v", key, err)
		}
	}
	repo["edit.toml"] = file("[[mounts]]\npath = \"{git}/config\"\nedit = { format = \"git-config\", safe = [\"branch.*.merge = refs/heads/**\", \"core.autocrlf = *\"] }\n")
	if _, err := l.Load("repo:edit"); err != nil {
		t.Errorf("a setting that runs nothing is refused: %v", err)
	}
}

func TestARepositoryProfileCannotMountPrivatePaths(t *testing.T) {
	l := repoLoader()
	l.Home, l.Private = "/home/u", []string{"/home/u/.local/state/doriath", "/home/u/.ssh"}
	repo := l.Repository.(fstest.MapFS)
	for _, path := range []string{"~/.local/state/doriath", "~/.local/state/doriath/grants", "~/.local", "/home/u/.ssh"} {
		repo["mount.toml"] = file("[[mounts]]\npath = \"" + path + "\"\nmode = \"write\"\n")
		_, err := l.Load("repo:mount")
		if err == nil || !strings.Contains(err.Error(), "a repository profile cannot show") {
			t.Errorf("%s: err = %v", path, err)
		}
	}
	repo["mount.toml"] = file("[[mounts]]\npath = \"~/.local/share/fonts\"\n\n[[mounts]]\npath = \"~/.ssh\"\nmode = \"hide\"\n")
	if _, err := l.Load("repo:mount"); err != nil {
		t.Errorf("a mount of another path is refused: %v", err)
	}
	l.Profiles.(fstest.MapFS)["mine.toml"] = file("[[mounts]]\npath = \"~/.ssh\"\n")
	if _, err := l.Load("mine"); err != nil {
		t.Errorf("your own profile cannot mount it: %v", err)
	}
}

const namesASecret = "[[http]]\nhost = \"proj.example\"\ncredential = { secret = \"proj\" }\n"

const attachesASecret = "[secrets.proj]\nkeyring = true\n\n[[http]]\nhost = \"proj.example\"\ncredential = { secret = \"proj\" }\n"

func TestARepositoryProfileNamesASecretOnTheHostYourProfileAttachesItTo(t *testing.T) {
	l := repoLoader()
	l.Profiles.(fstest.MapFS)["mine.toml"] = file(attachesASecret)
	l.Repository.(fstest.MapFS)["named.toml"] = file(namesASecret)
	p, err := l.Load("mine+repo:named")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Secrets["proj"].Keyring {
		t.Errorf("secret proj = %+v", p.Secrets["proj"])
	}
	if _, ok := p.Intercepted("proj.example"); !ok {
		t.Error("proj.example is not intercepted")
	}
	l.Repository.(fstest.MapFS)["changed.toml"] = file("[[http]]\nhost = \"proj.example\"\ncredential = { secret = \"proj\", scheme = \"basic\", username = \"x\" }\n")
	if _, err := l.Load("mine+repo:changed"); err == nil || !strings.Contains(err.Error(), "already give it a credential") {
		t.Errorf("a changed credential on the same host: %v", err)
	}
}

func TestARepositoryProfileCannotSendYourSecretToAnotherHost(t *testing.T) {
	l := repoLoader()
	l.Profiles.(fstest.MapFS)["mine.toml"] = file(attachesASecret)
	l.Repository.(fstest.MapFS)["other.toml"] = file("[[http]]\nhost = \"evil.example\"\ncredential = { secret = \"proj\" }\n")
	_, err := l.Load("mine+repo:other")
	want := `http evil.example: secret "proj": a repository profile can send a secret only to a host that your own profile already attaches it to. Attach "proj" to evil.example in a profile of your own first`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

func TestARepositoryProfileUsesYourSecretWithAnMCPServerOnlyAtYourURL(t *testing.T) {
	l := repoLoader()
	l.Profiles.(fstest.MapFS)["mine.toml"] = file("[secrets.docs]\nkeyring = true\n\n[[mcp]]\nname = \"docs\"\nurl = \"https://mcp.docs.example/mcp\"\nsecret = \"docs\"\n")
	repo := l.Repository.(fstest.MapFS)
	repo["same.toml"] = file("[[mcp]]\nname = \"docs-again\"\nurl = \"https://mcp.docs.example/mcp\"\nsecret = \"docs\"\n")
	repo["other.toml"] = file("[[mcp]]\nname = \"evil\"\nurl = \"https://evil.example/mcp\"\nsecret = \"docs\"\n")
	if _, err := l.Load("mine+repo:same"); err != nil {
		t.Fatalf("the same URL: %v", err)
	}
	_, err := l.Load("mine+repo:other")
	want := `mcp server https://evil.example/mcp: secret "docs": a repository profile can use a secret only with a URL that your own profile already uses it with. Add an [[mcp]] with this url and secret to a profile of your own first`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

func TestARepositoryProfileSigningKeyMayNameYourSecret(t *testing.T) {
	l := repoLoader()
	l.Profiles.(fstest.MapFS)["mine.toml"] = file("[secrets.key]\nkeyring = true\n")
	l.Repository.(fstest.MapFS)["sign.toml"] = file("[signing]\nkey = \"key\"\n")
	if _, err := l.Load("mine+repo:sign"); err != nil {
		t.Fatal(err)
	}
}

func TestARepositoryProfileThatNamesASecretNobodyGivesSaysWhatToAdd(t *testing.T) {
	l := repoLoader()
	l.Repository.(fstest.MapFS)["named.toml"] = file(namesASecret)
	_, err := l.Load("work+repo:named")
	if err == nil || !strings.Contains(err.Error(), `add it under [secrets.proj]`) {
		t.Fatalf("err = %v", err)
	}
}

func TestARepositoryProfileCannotMintTokensWithYourKey(t *testing.T) {
	l := repoLoader()
	l.Repository.(fstest.MapFS)["app.toml"] = file("[secrets.github]\ngithub_app = { app_id = 1, key = \"k\", permissions = { contents = \"read\" } }\n")
	_, err := l.Load("work+repo:app")
	if err == nil || !strings.Contains(err.Error(), `secret "github": a repository profile cannot mint tokens with a key of yours`) || !strings.Contains(err.Error(), "my-app+repo:app") {
		t.Fatalf("err = %v", err)
	}
}

func TestARepositoryProfileCannotReachPortsNameCodeOrChangeAModuleHost(t *testing.T) {
	l := repoLoader()
	l.Modules = append(l.Modules, modules.FS)
	repo := l.Repository.(fstest.MapFS)
	for _, c := range []struct{ name, body, want string }{
		{"tcp", "[egress]\ntcp_ports = [5432]\n", "egress port 5432: a repository profile cannot reach a port on your machine"},
		{"http-port", "[egress]\nports = [8080]\n", "egress port 8080"},
		{"libraries", "[code]\nlibraries = [\"/work/lib.so\"]\n", "code: a repository profile cannot name archives or libraries"},
		{"archives", "[code]\narchives = [\"/work/a.jar\"]\n", "code: a repository profile cannot name archives or libraries"},
		{"module-host-rule", "modules = [\"cdns\"]\n\n[[http]]\nhost = \"storage.googleapis.com\"\n\n[[http.rules]]\nmethod = \"*\"\npath = \"/**\"\naction = \"allow\"\n", "http storage.googleapis.com: your profiles or modules already define storage.googleapis.com"},
		{"module-host-default", "modules = [\"cdns\"]\n\n[[http]]\nhost = \"storage.googleapis.com\"\ndefault = \"allow\"\n", "cannot add rules or settings"},
		{"module-wildcard-host", "modules = [\"aws\"]\n\n[[http]]\nhost = \"ec2.us-east-1.amazonaws.com\"\ndefault = \"allow\"\n", "already give it a credential"},
	} {
		repo[c.name+".toml"] = file(c.body)
		_, err := l.Load("repo:" + c.name)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
}

func TestTheSourcesOfAProfileListItsPortsCodeAndRules(t *testing.T) {
	l := repoLoader()
	l.Modules = append(l.Modules, modules.FS)
	l.Profiles.(fstest.MapFS)["mine.toml"] = file("modules = [\"claude\"]\n\n[egress]\ntcp_ports = [5432]\nports = [8080]\n\n[code]\nlibraries = [\"/opt/lib.so\"]\n\n[[http]]\nhost = \"plain.example\"\n\n[[http.rules]]\nmethod = \"GET\"\npath = \"/**\"\naction = \"allow\"\n")
	p, err := l.Load("mine")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"port 5432: TCP", "port 8080: HTTP", "code library /opt/lib.so", "rule plain.example GET /**: allow"} {
		if p.Sources[key] == nil {
			t.Errorf("%q is not in the sources", key)
		}
	}
	for key := range p.Sources {
		if strings.HasPrefix(key, "rule api.anthropic.com") {
			t.Errorf("a module lists its rules in the sources: %q", key)
		}
	}
}

func TestARepositoryProfileCannotMountTheRuntimeDirectory(t *testing.T) {
	l := repoLoader()
	l.Home, l.Private = "/home/u", []string{"/run/user/1000/doriath"}
	repo := l.Repository.(fstest.MapFS)
	for _, path := range []string{"/run/user/1000/doriath/sessions", "/run/user/1000"} {
		repo["mount.toml"] = file("[[mounts]]\npath = \"" + path + "\"\nmode = \"read\"\n")
		if _, err := l.Load("repo:mount"); err == nil || !strings.Contains(err.Error(), "a repository profile cannot show") {
			t.Errorf("%s: err = %v", path, err)
		}
	}
}
