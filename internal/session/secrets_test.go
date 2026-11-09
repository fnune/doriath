package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/oauth"
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
	if text := st.Describe(); !strings.Contains(text, "acme (requests to api.acme.com)") || !strings.Contains(text, "exit status 1") {
		t.Errorf("describe lacks the missing secret:\n%s", text)
	}
	if text := st.Describe(); strings.Contains(text, "not logged in") {
		t.Errorf("the jail sees what the secret command printed:\n%s", text)
	}
	if text := s.hostStatus().Describe(); !strings.Contains(text, "not logged in") {
		t.Errorf("your status lacks what the command printed:\n%s", text)
	}
	if !strings.Contains(s.notes[0].text, "not logged in") {
		t.Errorf("your note lacks what the command printed: %v", s.notes)
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
	s.dismissedSecrets["acme"] = true
	if err := s.fetchSecrets(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.provide("acme", secret.NewValue([]byte("s3cr3t-v4lue"))); err != nil {
		t.Fatal(err)
	}
	if st := s.status(); len(st.Unavailable) != 0 {
		t.Errorf("unavailable after provide = %+v", st.Unavailable)
	}
	if log := s.audit.String(); !strings.Contains(log, `"secret-provided"`) || strings.Contains(log, "s3cr3t-v4lue") {
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

func TestAFailingSecretShowsOneCardAndTellsTheAgentWhatToWaitFor(t *testing.T) {
	s := sessionWithSecrets(t, map[string]secret.Backend{"acme": {Command: []string{"acme-token"}}})
	for range 2 {
		_, err := carding{s.Session}.Get(context.Background(), "acme")
		if err == nil || !strings.Contains(err.Error(), "doriath asked the user to fix it on the approvals page") || !strings.Contains(err.Error(), "`doriath request wait ") {
			t.Fatalf("err = %v", err)
		}
	}
	pending := s.manager.Pending()
	if len(pending) != 1 || pending[0].Kind != approval.KindSecret || pending[0].Command != "doriath secrets provide --session s1 acme" {
		t.Fatalf("pending = %+v", pending)
	}
}

func TestDismissingASecretCardStopsTheCardsForIt(t *testing.T) {
	s := sessionWithSecrets(t, map[string]secret.Backend{"acme": {Command: []string{"acme-token"}}})
	_, _ = carding{s.Session}.Get(context.Background(), "acme")
	card := s.manager.Pending()[0]
	if err := s.manager.Decide(card.ID, approval.Decision{Verdict: approval.VerdictDeny}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		done := s.dismissedSecrets["acme"]
		s.mu.Unlock()
		if done {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, err := carding{s.Session}.Get(context.Background(), "acme")
	if err == nil || strings.Contains(err.Error(), "approvals page") || len(s.manager.Pending()) != 0 {
		t.Errorf("after dismiss: err = %v, pending = %+v", err, s.manager.Pending())
	}
}

func TestAnOAuthCardNamesTheLoginCommand(t *testing.T) {
	s := sessionWithSecrets(t, map[string]secret.Backend{"linear": {OAuth: &secret.OAuth{MCP: "https://mcp.linear.app/mcp"}}})
	s.secretCard("linear", errors.New("not signed in"))
	if p := s.manager.Pending(); len(p) != 1 || p[0].Command != "doriath profiles login deploy linear" {
		t.Errorf("pending = %+v", p)
	}
}

func TestAKeyringCardNamesTheLoginCommand(t *testing.T) {
	s := sessionWithSecrets(t, map[string]secret.Backend{"forge": {Keyring: true}})
	s.secretCard("forge", errors.New("not in the keyring"))
	if p := s.manager.Pending(); len(p) != 1 || p[0].Command != "doriath profiles login deploy forge" {
		t.Errorf("pending = %+v", p)
	}
}

type countingLogins struct{ calls int }

func (c *countingLogins) Token(_ context.Context, name string, _ secret.OAuth) (secret.Value, error) {
	c.calls++
	return secret.Value{}, errors.New(`secret "` + name + `": not signed in`)
}

func TestAMissingOAuthLoginCountsAsMissingAtStart(t *testing.T) {
	backends := map[string]secret.Backend{"linear": {OAuth: &secret.OAuth{MCP: "https://mcp.linear.app/mcp"}}}
	s := sessionWithSecrets(t, backends)
	logins := &countingLogins{}
	s.deps.Secrets = secret.NewConfigured(backends, failingRunner{}, secret.OSFiles{}).WithOAuth(logins)
	if err := s.fetchSecrets(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := s.status()
	if len(st.Unavailable) != 1 || st.Unavailable[0].Secret != "linear" {
		t.Errorf("unavailable = %+v", st.Unavailable)
	}
	if got := st.SecretsSummary(80); got != "secrets missing linear" {
		t.Errorf("summary = %q", got)
	}
}

func TestASignedInOAuthLoginIsNotFetchedAtStart(t *testing.T) {
	backends := map[string]secret.Backend{"linear": {OAuth: &secret.OAuth{MCP: "https://mcp.linear.app/mcp"}}}
	s := sessionWithSecrets(t, backends)
	logins := &countingLogins{}
	s.deps.Secrets = secret.NewConfigured(backends, failingRunner{}, secret.OSFiles{}).WithOAuth(logins)
	state := oauth.StatePath(s.deps.Paths.State, "deploy", "linear")
	if err := os.MkdirAll(filepath.Dir(state), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.fetchSecrets(context.Background()); err != nil {
		t.Fatal(err)
	}
	if logins.calls != 0 {
		t.Errorf("a signed-in login was fetched at start %d times", logins.calls)
	}
}
