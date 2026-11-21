package modules

import (
	"context"
	"io/fs"
	"net/http"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/fnune/doriath/internal/keyringtest"
	"github.com/fnune/doriath/internal/oauth"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/secret"
)

func loadWithClaude(t *testing.T, profiles map[string]string, name string) (*profile.Profile, error) {
	t.Helper()
	fsys := fstest.MapFS{}
	for n, body := range profiles {
		fsys[n+".toml"] = &fstest.MapFile{Data: []byte(body)}
	}
	return (&profile.Loader{Profiles: fsys, Modules: []fs.FS{FS}, Home: "/home/u"}).Load(name)
}

func TestTheClaudeModuleGivesTheLoginAndTheCredential(t *testing.T) {
	p, err := loadWithClaude(t, map[string]string{"app": `modules = ["claude"]`}, "app")
	if err != nil {
		t.Fatal(err)
	}
	o := p.Secrets["claude"].OAuth
	if o == nil || o.AuthorizeURL != "https://claude.com/cai/oauth/authorize" || o.TokenURL != "https://platform.claude.com/v1/oauth/token" || o.TokenBody != "json" || o.ClientID != "9d1c250a-e61b-44d9-88ed-5944d1962f5e" {
		t.Fatalf("oauth = %+v", o)
	}
	if !p.Secrets["claude"].Required {
		t.Error("a session without the login must stop before the agent starts")
	}
	h, ok := p.Intercepted("api.anthropic.com")
	if !ok || h.Credential == nil || h.Credential.Secret != "claude" || h.Credential.Scheme != profile.SchemeBearer || !slices.Equal(h.Credential.Binaries, []string{"claude"}) {
		t.Fatalf("credential = %+v", h.Credential)
	}
	site, ok := p.Intercepted("claude.ai")
	if !ok || site.Credential == nil || site.Credential.Secret != "claude" {
		t.Errorf("claude.ai credential = %+v", site)
	}
	if _, ok := p.Intercepted("mcp-proxy.anthropic.com"); ok || p.AllowsHost("mcp-proxy.anthropic.com") {
		t.Error("the connector proxy must stay refused")
	}
	placeholder := p.Env.Set["CLAUDE_CODE_OAUTH_TOKEN"]
	if placeholder == "" || strings.HasPrefix(placeholder, "sk-ant-a") {
		t.Errorf("placeholder = %q", placeholder)
	}
	if r, _ := h.DecideRequest("POST", "/v1/messages", http.Header{"Authorization": {"Bearer " + placeholder}}, nil); r.Action == profile.ActionDeny {
		t.Error("the placeholder is denied")
	}
	for name, header := range map[string]http.Header{"an API key": {"X-Api-Key": {"sk-ant-x"}}, "an API key as a bearer": {"Authorization": {"Bearer sk-ant-api03-x"}}} {
		if r, _ := h.DecideRequest("POST", "/v1/messages", header, nil); r.Action != profile.ActionDeny {
			t.Errorf("%s = %v, want deny", name, r.Action)
		}
	}
	if r, _ := h.Decide("POST", "/api/event_logging/v2/batch", nil); r.Action != profile.ActionDeny {
		t.Error("usage events are not denied")
	}
}

func TestAJailedClaudeCannotSignInByItself(t *testing.T) {
	p, err := loadWithClaude(t, map[string]string{"app": `modules = ["claude"]`}, "app")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ host, path string }{{"claude.com", "/cai/oauth/authorize"}, {"platform.claude.com", "/oauth/authorize"}} {
		if r, ok := p.OpenRule(c.host, c.path); ok && r.Action == profile.ActionAllow {
			t.Errorf("the sign-in page %s%s opens without a question", c.host, c.path)
		}
	}
}

func TestEveryProfileWithTheClaudeModuleSharesOneLogin(t *testing.T) {
	profiles := map[string]string{"one": `modules = ["claude"]`, "two": `modules = ["claude"]`}
	one, err := loadWithClaude(t, profiles, "one")
	if err != nil {
		t.Fatal(err)
	}
	two, err := loadWithClaude(t, profiles, "two+one")
	if err != nil {
		t.Fatal(err)
	}
	if one.SecretOwner("claude") != "module:claude" || two.SecretOwner("claude") != "module:claude" {
		t.Errorf("owners = %q, %q", one.SecretOwner("claude"), two.SecretOwner("claude"))
	}
	if one.LoginProfile("claude") != "one" || two.LoginProfile("claude") != "two+one" {
		t.Errorf("login profiles = %q, %q", one.LoginProfile("claude"), two.LoginProfile("claude"))
	}
}

func TestWithoutALoginTheSessionNamesTheCommandToRun(t *testing.T) {
	p, err := loadWithClaude(t, map[string]string{"app": `modules = ["claude"]`}, "app")
	if err != nil {
		t.Fatal(err)
	}
	logins := keyringtest.New()
	store := secret.NewConfigured(p.Secrets, nil).WithOAuth(oauth.NewTokensOwnedBy(logins, p.SecretOwner).WithLoginProfile(p.LoginProfile))
	_, err = store.Get(context.Background(), "claude")
	if err == nil || !strings.Contains(err.Error(), "not signed in: run `doriath profiles login app claude`") {
		t.Fatalf("err = %v", err)
	}
	if err := logins.Write("module:claude", "claude", secret.NewValue([]byte(`{"token":{"access_token":"the-login"}}`))); err != nil {
		t.Fatal(err)
	}
	v, err := store.Get(context.Background(), "claude")
	if err != nil || string(v.Reveal()) != "the-login" {
		t.Errorf("with a login = %q, %v", v.Reveal(), err)
	}
}

func TestAProfileCanReplaceTheLoginOfTheClaudeModule(t *testing.T) {
	p, err := loadWithClaude(t, map[string]string{"app": "modules = [\"claude\"]\n\n[secrets.claude]\ncommand = [\"my-claude-token\"]\n"}, "app")
	if err != nil {
		t.Fatal(err)
	}
	b := p.Secrets["claude"]
	if b.OAuth != nil || len(b.Command) != 1 || b.Required {
		t.Errorf("secret = %+v", b)
	}
	if p.SecretOwner("claude") != "app" || p.LoginProfile("claude") != "app" {
		t.Errorf("owner = %q", p.SecretOwner("claude"))
	}
}

func TestOnlyABuiltInModuleCanDefineALogin(t *testing.T) {
	user := fstest.MapFS{"mine.toml": {Data: []byte("uses_secrets = [\"x\"]\n[secrets.x.oauth]\nissuer = \"https://a.example\"\nclient_id = \"c\"\n")}}
	l := &profile.Loader{Profiles: fstest.MapFS{"app.toml": {Data: []byte(`modules = ["mine"]`)}}, Modules: []fs.FS{user}, Home: "/home/u"}
	if _, err := l.Load("app"); err == nil || !strings.Contains(err.Error(), `module "mine": name and secrets belong in profiles`) {
		t.Errorf("a module of yours: %v", err)
	}
	shipped := shippedMap{fstest.MapFS{"cmd.toml": {Data: []byte("[secrets.x]\ncommand = [\"true\"]\n")}}}
	l = &profile.Loader{Profiles: fstest.MapFS{"app.toml": {Data: []byte(`modules = ["cmd"]`)}}, Modules: []fs.FS{shipped}, Home: "/home/u"}
	if _, err := l.Load("app"); err == nil || !strings.Contains(err.Error(), `a built-in module can define only a login with oauth`) {
		t.Errorf("a built-in module with a command: %v", err)
	}
}

func TestARepositoryProfileCannotReplaceTheLoginOfTheClaudeModule(t *testing.T) {
	l := &profile.Loader{
		Profiles:       fstest.MapFS{"app.toml": {Data: []byte(`modules = ["claude"]`)}},
		Modules:        []fs.FS{FS},
		Repository:     fstest.MapFS{"dev.toml": {Data: []byte("[secrets.claude.oauth]\nissuer = \"https://evil.example\"\nclient_id = \"c\"\n")}},
		RepositoryRoot: "/home/u/src/app",
		Home:           "/home/u",
	}
	if _, err := l.Load("app+repo:dev"); err == nil || !strings.Contains(err.Error(), `secret "claude": your profiles or modules already define it`) {
		t.Errorf("err = %v", err)
	}
}
