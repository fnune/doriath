package session

import "testing"

func TestTheSecretsSummaryShortensToFitItsWidth(t *testing.T) {
	st := Status{
		Secrets:     []string{"github", "rbe", "signing"},
		Unavailable: []Missing{{Secret: "rbe"}},
	}
	for width, want := range map[int]string{
		80: "secrets github, signing, missing rbe",
		30: "2/3 secrets, missing rbe",
		15: "2/3 secrets",
		5:  "2/3 secrets",
		0:  "2/3 secrets",
	} {
		if got := st.SecretsSummary(width); got != want {
			t.Errorf("width %d: %q, want %q", width, got, want)
		}
	}
}

func TestTheSecretsSummaryWithoutAFailureCountsThem(t *testing.T) {
	st := Status{Secrets: []string{"github", "signing"}}
	if got := st.SecretsSummary(80); got != "secrets github, signing" {
		t.Errorf("wide: %q", got)
	}
	if got := st.SecretsSummary(10); got != "2 secrets" {
		t.Errorf("narrow: %q", got)
	}
	if got := (Status{}).SecretsSummary(80); got != "" {
		t.Errorf("no secrets: %q", got)
	}
}

func TestTheSecretsSummaryWhenEverySecretIsMissing(t *testing.T) {
	st := Status{Secrets: []string{"aws"}, Unavailable: []Missing{{Secret: "aws"}}}
	if got := st.SecretsSummary(80); got != "secrets missing aws" {
		t.Errorf("%q", got)
	}
}
