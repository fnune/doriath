package session

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/secret"
)

type failingRunner struct{}

func (failingRunner) Output(context.Context, secret.Command) ([]byte, []byte, error) {
	return nil, []byte("not logged in"), errors.New("exit status 1")
}

func sessionWithSecrets(t *testing.T, backends map[string]secret.Backend) *testSession {
	t.Helper()
	s := newTestSession(t, &answering{})
	s.deps.Secrets = secret.NewConfigured(backends, failingRunner{}, secret.OSFiles{})
	s.req.Profile = &profile.Profile{
		Name:    "deploy",
		Secrets: backends,
		HTTP:    []profile.HTTPHost{{Host: "api.acme.com", Credential: &profile.Credential{Secret: "acme"}}},
	}
	return s
}

func TestASessionStartsWithoutAnOptionalSecretAndSaysWhatFails(t *testing.T) {
	s := sessionWithSecrets(t, map[string]secret.Backend{"acme": {Command: []string{"acme-token"}}})
	if err := s.fetchSecrets(context.Background()); err != nil {
		t.Fatalf("an optional secret stopped the session: %v", err)
	}
	if len(s.notes) != 1 || !strings.Contains(s.notes[0].text, `secret "acme"`) || !strings.Contains(s.notes[0].text, "requests to api.acme.com") {
		t.Errorf("notes = %v", s.notes)
	}
	st := s.status()
	if len(st.Unavailable) != 1 || st.Unavailable[0].Secret != "acme" {
		t.Fatalf("unavailable = %+v", st.Unavailable)
	}
	if text := st.Describe(); !strings.Contains(text, "acme (requests to api.acme.com)") || !strings.Contains(text, "not logged in") {
		t.Errorf("describe lacks the missing secret:\n%s", text)
	}
}

func TestARequiredSecretStopsTheSession(t *testing.T) {
	s := sessionWithSecrets(t, map[string]secret.Backend{"acme": {Command: []string{"acme-token"}, Required: true}})
	if err := s.fetchSecrets(context.Background()); err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Fatalf("err = %v", err)
	}
}

func TestAProvidedSecretLeavesTheStatusAndTheAuditLogNamesIt(t *testing.T) {
	s := sessionWithSecrets(t, map[string]secret.Backend{"acme": {Command: []string{"acme-token"}}})
	if err := s.fetchSecrets(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.provide("acme", secret.NewValue([]byte("tok"))); err != nil {
		t.Fatal(err)
	}
	if st := s.status(); len(st.Unavailable) != 0 {
		t.Errorf("unavailable after provide = %+v", st.Unavailable)
	}
	if log := s.audit.String(); !strings.Contains(log, `"secret-provided"`) || strings.Contains(log, "tok") {
		t.Errorf("audit log = %s", log)
	}
}

func TestTheSigningKeyCannotBeProvided(t *testing.T) {
	s := sessionWithSecrets(t, map[string]secret.Backend{"signing": {File: "/k", Required: true}})
	s.req.Profile.SigningKey = "signing"
	if err := s.provide("signing", secret.NewValue([]byte("key"))); err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Errorf("err = %v", err)
	}
}
