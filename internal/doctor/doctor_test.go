package doctor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/profile"
)

type countingRunner struct{ runs int }

func (r *countingRunner) Output(context.Context, []string, bool) ([]byte, []byte, error) {
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
