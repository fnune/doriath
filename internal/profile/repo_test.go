package profile

import (
	"strings"
	"testing"
	"testing/fstest"
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
		"my-dev.toml": file("[egress]\nallow = [\"mine.example\"]\n\n[secrets.token]\nfile = \"~/.config/doriath/keys/token\"\n"),
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
		t.Fatalf("a secret from a file is refused: %v", err)
	}
}
