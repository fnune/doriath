package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/oauth"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/secret"
)

func loginProfile(secretBackend secret.Backend) *profile.Profile {
	return &profile.Profile{
		Name:    "work",
		MCP:     []profile.MCPServer{{Name: "linear", URL: "https://mcp.linear.app/mcp", Secret: "linear"}},
		Secrets: map[string]secret.Backend{"linear": secretBackend},
		HTTP:    []profile.HTTPHost{{Host: "mcp.linear.app", Default: profile.ActionApprove}},
	}
}

func refused(h profile.HTTPHost, method, path string) bool {
	for _, r := range h.Rules {
		if r.Method == method && r.Path.Match(path) {
			return r.Action == profile.ActionDeny
		}
	}
	return false
}

func TestTheAgentCannotSignInWhereDoriathHoldsTheLogin(t *testing.T) {
	state := t.TempDir()
	path := oauth.StatePath(state, "work", "linear")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"client_id":"c","token_url":"https://mcp.linear.app/oauth2/token","registration_url":"https://mcp.linear.app/oauth2/register","token":{"access_token":"a"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h := refuseOwnLogins(loginProfile(secret.Backend{OAuth: &secret.OAuth{MCP: "https://mcp.linear.app/mcp"}}), state).HTTP[0]
	for _, p := range []string{"/oauth2/token", "/oauth2/register"} {
		if !refused(h, "POST", p) {
			t.Errorf("POST %s goes through", p)
		}
	}
	if refused(h, "GET", "/.well-known/oauth-authorization-server") {
		t.Error("the metadata is refused")
	}
	if !strings.Contains(h.Rules[0].Summary, "doriath profiles login work linear") {
		t.Errorf("summary = %q", h.Rules[0].Summary)
	}
}

func TestWithoutASavedLoginTheCommonSignInPathsAreRefused(t *testing.T) {
	h := refuseOwnLogins(loginProfile(secret.Backend{OAuth: &secret.OAuth{MCP: "https://mcp.linear.app/mcp"}}), t.TempDir()).HTTP[0]
	for _, p := range []string{"/token", "/oauth/token", "/register"} {
		if !refused(h, "POST", p) {
			t.Errorf("POST %s goes through", p)
		}
	}
}

func TestASecretThatIsNoLoginLeavesTheHostAlone(t *testing.T) {
	h := refuseOwnLogins(loginProfile(secret.Backend{Command: []string{"pass", "linear"}}), t.TempDir()).HTTP[0]
	if len(h.Rules) != 0 {
		t.Errorf("rules = %+v", h.Rules)
	}
}
