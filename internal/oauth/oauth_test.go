package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/fnune/doriath/internal/keyringtest"
	"github.com/fnune/doriath/internal/secret"
)

type fakeServer struct {
	*httptest.Server
	mu        sync.Mutex
	grants    []string
	noRefresh bool
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{}
	mux := http.NewServeMux()
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	writeJSON := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer access-1" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp"`, f.URL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{}})
	})
	mux.HandleFunc("/public-mcp", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{}})
	})
	resource := func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"resource": f.URL + "/mcp", "authorization_servers": []string{f.URL}})
	}
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", resource)
	mux.HandleFunc("/.well-known/oauth-protected-resource", resource)
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                f.URL,
			"authorization_endpoint":                f.URL + "/authorize",
			"token_endpoint":                        f.URL + "/token",
			"registration_endpoint":                 f.URL + "/register",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"none"},
		})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		var meta map[string]any
		_ = json.NewDecoder(r.Body).Decode(&meta)
		meta["client_id"] = "registered-client"
		writeJSON(w, http.StatusCreated, meta)
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
			http.Error(w, "PKCE required", http.StatusBadRequest)
			return
		}
		back, _ := url.Parse(q.Get("redirect_uri"))
		back.RawQuery = url.Values{"code": {"the-code"}, "state": {q.Get("state")}}.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.grants = append(f.grants, r.Form.Get("grant_type"))
		noRefresh := f.noRefresh
		f.mu.Unlock()
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			if r.Form.Get("code") != "the-code" || r.Form.Get("code_verifier") == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
				return
			}
			tok := map[string]any{"access_token": "access-1", "refresh_token": "refresh-1", "token_type": "Bearer", "expires_in": 3600}
			if noRefresh {
				delete(tok, "refresh_token")
			}
			writeJSON(w, http.StatusOK, tok)
		case "refresh_token":
			if r.Form.Get("refresh_token") != "refresh-1" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"access_token": "access-2", "refresh_token": "refresh-2", "token_type": "Bearer", "expires_in": 3600})
		}
	})
	return f
}

type browser struct{ t *testing.T }

func (b browser) Open(u string) error {
	go func() {
		resp, err := http.Get(u)
		if err != nil {
			b.t.Errorf("browser: %v", err)
			return
		}
		defer resp.Body.Close()
		if page, err := io.ReadAll(resp.Body); err != nil || !strings.Contains(string(page), "You can close this tab.") {
			b.t.Errorf("browser: the callback page %q did not arrive whole: %v", page, err)
		}
	}()
	return nil
}

func TestLoginToAnMCPServerAndRefresh(t *testing.T) {
	f := newFakeServer(t)
	logins := keyringtest.New()
	var out strings.Builder
	if err := Login(context.Background(), secret.OAuth{MCP: f.URL + "/mcp"}, logins, "work", "notion", browser{t}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	s, err := load(logins, "work", "notion")
	if err != nil || s.ClientID != "registered-client" || s.Token.RefreshToken != "refresh-1" {
		t.Fatalf("state = %+v, %v", s, err)
	}

	tokens := NewTokens(logins, "work")
	v, err := tokens.Token(context.Background(), "notion", secret.OAuth{})
	if err != nil || string(v.Reveal()) != "access-1" {
		t.Fatalf("token = %q, %v", v.Reveal(), err)
	}

	s.Token.Expiry = time.Now().Add(-time.Minute)
	if err := s.save(logins, "work", "notion"); err != nil {
		t.Fatal(err)
	}
	v, err = NewTokens(logins, "work").Token(context.Background(), "notion", secret.OAuth{})
	if err != nil || string(v.Reveal()) != "access-2" {
		t.Fatalf("refreshed token = %q, %v", v.Reveal(), err)
	}
	if s, _ := load(logins, "work", "notion"); s.Token.RefreshToken != "refresh-2" {
		t.Errorf("a rotated refresh token must be saved: %+v", s.Token)
	}
}

func TestLoginWithAnIssuer(t *testing.T) {
	f := newFakeServer(t)
	logins := keyringtest.New()
	if err := Login(context.Background(), secret.OAuth{Issuer: f.URL, ClientID: "my-client", Scopes: []string{"read"}}, logins, "work", "google", browser{t}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if s, err := load(logins, "work", "google"); err != nil || s.ClientID != "my-client" || s.Token.AccessToken != "access-1" {
		t.Fatalf("state = %+v, %v", s, err)
	}
}

func TestTokenWithoutLoginNamesTheCommand(t *testing.T) {
	_, err := NewTokens(keyringtest.New(), "work").Token(context.Background(), "notion", secret.OAuth{})
	if err == nil || !strings.Contains(err.Error(), "doriath profiles login work notion") {
		t.Fatalf("err = %v", err)
	}
}

type callbackBrowser struct {
	t       *testing.T
	answer  func(signIn url.Values) url.Values
	openErr error
}

func (b callbackBrowser) Open(u string) error {
	signIn, err := url.Parse(u)
	if err != nil {
		return err
	}
	back, err := url.Parse(signIn.Query().Get("redirect_uri"))
	if err != nil {
		return err
	}
	back.RawQuery = b.answer(signIn.Query()).Encode()
	if err := (browser{b.t}).Open(back.String()); err != nil {
		return err
	}
	return b.openErr
}

func TestRefusedSignInSaysWhatTheServerSaid(t *testing.T) {
	f := newFakeServer(t)
	logins := keyringtest.New()
	refuse := callbackBrowser{t: t, answer: func(url.Values) url.Values {
		return url.Values{"error": {"access_denied"}, "error_description": {"you said no"}}
	}}
	err := Login(context.Background(), secret.OAuth{MCP: f.URL + "/mcp"}, logins, "work", "notion", refuse, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "the server refused the sign-in: access_denied you said no") {
		t.Fatalf("err = %v", err)
	}
	if logins.Has("work", "notion") {
		t.Fatal("a refused sign-in must save nothing")
	}
}

func TestSignInMustAnswerTheRequestDoriathMade(t *testing.T) {
	f := newFakeServer(t)
	forge := callbackBrowser{t: t, answer: func(url.Values) url.Values {
		return url.Values{"code": {"the-code"}, "state": {"another"}}
	}}
	err := Login(context.Background(), secret.OAuth{Issuer: f.URL, ClientID: "my-client"}, keyringtest.New(), "work", "s", forge, io.Discard)
	if err == nil || err.Error() != "the sign-in answered for another request" {
		t.Fatalf("err = %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.grants) != 0 {
		t.Fatalf("a code from another request was exchanged: %v", f.grants)
	}
}

func TestLoginRefusesAServerThatAsksNoLogin(t *testing.T) {
	f := newFakeServer(t)
	err := Login(context.Background(), secret.OAuth{MCP: f.URL + "/public-mcp"}, keyringtest.New(), "work", "s", browser{t}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "answered 200 OK, not 401: it does not ask for a login") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoginSaysWhatYouMustDoYourself(t *testing.T) {
	f := newFakeServer(t)
	f.mu.Lock()
	f.noRefresh = true
	f.mu.Unlock()
	noBrowser := callbackBrowser{t: t, openErr: errors.New("no display"), answer: func(signIn url.Values) url.Values {
		return url.Values{"code": {"the-code"}, "state": {signIn.Get("state")}}
	}}
	var out strings.Builder
	if err := Login(context.Background(), secret.OAuth{Issuer: f.URL, ClientID: "my-client"}, keyringtest.New(), "work", "s", noBrowser, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Sign in at:\n  " + f.URL + "/authorize?", "Open it in your browser on this machine.", "The server gave no refresh token"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestRevokedLoginAsksYouToSignInAgain(t *testing.T) {
	f := newFakeServer(t)
	logins := keyringtest.New()
	expired := &oauth2.Token{AccessToken: "old", RefreshToken: "revoked", Expiry: time.Now().Add(-time.Minute)}
	if err := (State{ClientID: "c", TokenURL: f.URL + "/token", Token: expired}).save(logins, "work", "notion"); err != nil {
		t.Fatal(err)
	}
	_, err := NewTokens(logins, "work").Token(context.Background(), "notion", secret.OAuth{})
	if err == nil || !strings.HasPrefix(err.Error(), `secret "notion": refresh the login: `) || !strings.HasSuffix(err.Error(), "; run `doriath profiles login work notion` again") {
		t.Fatalf("err = %v", err)
	}
}

func TestDamagedLoginStateNamesTheEntry(t *testing.T) {
	for name, content := range map[string]string{"not JSON": "{", "no token": `{"client_id":"c"}`} {
		t.Run(name, func(t *testing.T) {
			logins := keyringtest.New()
			if err := logins.Write("work", "notion", secret.NewValue([]byte(content))); err != nil {
				t.Fatal(err)
			}
			_, err := NewTokens(logins, "work").Token(context.Background(), "notion", secret.OAuth{})
			if err == nil || !strings.Contains(err.Error(), "login work/notion in the keyring") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestWithoutAKeyringTheLoginIsUnavailableAndNoFileIsRead(t *testing.T) {
	dir := t.TempDir()
	writeOldLogin(t, dir, "notion", `{"token":{"access_token":"from-a-file"}}`)
	logins := keyringtest.New()
	logins.Err = errors.New("no secret service")
	_, err := NewTokens(logins, "work").Token(context.Background(), "notion", secret.OAuth{})
	if err == nil || !strings.Contains(err.Error(), "no secret service") {
		t.Fatalf("err = %v", err)
	}
}

func writeOldLogin(t *testing.T, stateDir, name, content string) string {
	t.Helper()
	path := filepath.Join(stateDir, "oauth", "work", name+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMigrateMovesOldLoginFilesIntoTheKeyring(t *testing.T) {
	dir := t.TempDir()
	old := `{"client_id":"c","token":{"access_token":"a","refresh_token":"r"}}`
	path := writeOldLogin(t, dir, "notion", old)
	writeOldLogin(t, dir, "newer", `{"token":{"access_token":"stale"}}`)
	leftover := path + ".tmp"
	if err := os.WriteFile(leftover, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	logins := keyringtest.New()
	if err := logins.Write("work", "newer", secret.NewValue([]byte(`{"token":{"access_token":"fresh"}}`))); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(dir, logins); err != nil {
		t.Fatal(err)
	}
	if v, err := logins.Read("work", "notion"); err != nil || string(v.Reveal()) != old {
		t.Errorf("moved login = %q, %v", v.Reveal(), err)
	}
	if v, _ := logins.Read("work", "newer"); string(v.Reveal()) != `{"token":{"access_token":"fresh"}}` {
		t.Errorf("a file replaced a newer login: %q", v.Reveal())
	}
	if _, err := os.Stat(filepath.Join(dir, "oauth")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("login files stay on disk: %v", err)
	}
	if err := Migrate(dir, logins); err != nil {
		t.Errorf("a second run: %v", err)
	}
}

func TestMigrateKeepsAFileWhenTheKeyringDoesNotAnswer(t *testing.T) {
	dir := t.TempDir()
	path := writeOldLogin(t, dir, "notion", `{"token":{"access_token":"a"}}`)
	logins := keyringtest.New()
	logins.Err = errors.New("no secret service")
	if err := Migrate(dir, logins); err == nil || !strings.Contains(err.Error(), "no secret service") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the login is gone, and nothing holds it: %v", err)
	}
}

func TestMigrateKeepsAFileThatHoldsNoLogin(t *testing.T) {
	dir := t.TempDir()
	path := writeOldLogin(t, dir, "notion", `{"client_id":"c"}`)
	logins := keyringtest.New()
	if err := Migrate(dir, logins); err == nil {
		t.Fatal("want an error")
	}
	if logins.Has("work", "notion") {
		t.Error("a file without a token became a login")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the file is gone: %v", err)
	}
}
