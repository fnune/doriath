package doctor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/secret"
)

type countingRunner struct{ runs int }

func (r *countingRunner) Output(context.Context, secret.Command) ([]byte, []byte, error) {
	r.runs++
	return []byte("token"), nil, nil
}

func TestSecretsOfAProfileYouDidNotAllowStayUnfetched(t *testing.T) {
	opts := repoOptions(t, "", map[string]string{"app": "[secrets.token]\ncommand = [\"sh\", \"-c\", \"echo token\"]\n"})
	runner := &countingRunner{}
	opts.FetchSecrets, opts.Runner = true, runner
	opts.Allow = func(*profile.Profile) error { return errors.New("you did not allow profile app") }
	profiles := []*profile.Profile{mustLoad(t, opts, "app")}
	results, _ := checkSecrets(context.Background(), opts, profiles)
	if runner.runs != 0 {
		t.Errorf("ran %d secret commands of a profile you did not allow", runner.runs)
	}
	if !strings.Contains(details(results), "problem secrets of profile app: you did not allow profile app") {
		t.Errorf("results:\n%s", details(results))
	}
	opts.Allow = func(*profile.Profile) error { return nil }
	checkSecrets(context.Background(), opts, profiles)
	if runner.runs != 1 {
		t.Errorf("ran %d secret commands of an allowed profile", runner.runs)
	}
}

func mustLoad(t *testing.T, opts Options, name string) *profile.Profile {
	t.Helper()
	p, err := opts.Loader.Load(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSecretsLeftOnDiskFailTheCheck(t *testing.T) {
	state := t.TempDir()
	p := config.Paths{State: state}
	if got := details(checkSecretsOnDisk(p)); got != "ok no secrets on disk: \n" {
		t.Errorf("a clean state directory: %q", got)
	}
	login := filepath.Join(state, "oauth", "work", "linear.json")
	if err := os.MkdirAll(filepath.Dir(login), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{login, filepath.Join(state, "web-token")} {
		if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	results := checkSecretsOnDisk(p)
	if !Failed(results) {
		t.Fatalf("results:\n%s", details(results))
	}
	got := details(results)
	for _, want := range []string{
		"problem secret on disk: " + login + " holds an OAuth login: run `doriath profiles login work` to move it into the keyring\n",
		"problem secret on disk: " + filepath.Join(state, "web-token") + " holds the token of the approvals page: run `doriath web open`, which deletes it\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("results lack %q:\n%s", want, got)
		}
	}
}

type failingRunner struct{ err error }

func (r failingRunner) Output(context.Context, secret.Command) ([]byte, []byte, error) {
	return nil, nil, r.err
}

func TestASecretLineDoesNotRepeatTheNameOfTheSecret(t *testing.T) {
	opts := repoOptions(t, "", map[string]string{"app": "[secrets.token]\ncommand = [\"sh\", \"-c\", \"false\"]\n\n[secrets.kept]\ncommand = [\"sh\", \"-c\", \"false\"]\nrequired = true\n\n[secrets.\"github:a:b\"]\ngithub_app = { app_id = 1, key = \"kept\", permissions = { contents = \"read\" } }\n"})
	opts.FetchSecrets, opts.Runner = true, failingRunner{errors.New("exit status 1")}
	opts.Allow = func(*profile.Profile) error { return nil }
	opts.Apps = failingApps{errors.New("no GitHub remote, so no token")}
	got := details(func() []Result {
		r, _ := checkSecrets(context.Background(), opts, []*profile.Profile{mustLoad(t, opts, "app")})
		return r
	}())
	for _, want := range []string{
		"problem secret app/kept: command sh: exit status 1\n",
		"note secret app/token: command sh: exit status 1: sessions start without it\n",
		"note secret app/github:a:b: the private key in \"kept\": command sh: exit status 1: sessions start without it\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("results lack %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, `secret "`) {
		t.Errorf("a line repeats the secret name:\n%s", got)
	}
}

type failingApps struct{ err error }

func (a failingApps) Mint(context.Context, secret.GitHubApp, secret.Value) (secret.Value, time.Time, error) {
	return secret.Value{}, time.Time{}, a.err
}
