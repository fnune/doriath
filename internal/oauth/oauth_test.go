package oauth

import (
	"context"
	"encoding/json"
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

	"github.com/fnune/girdle/internal/secret"
)

// fakeServer is an MCP server and the OAuth server it trusts, on one host.
type fakeServer struct {
	*httptest.Server
	mu     sync.Mutex
	grants []string
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
		f.mu.Unlock()
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			if r.Form.Get("code") != "the-code" || r.Form.Get("code_verifier") == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"access_token": "access-1", "refresh_token": "refresh-1", "token_type": "Bearer", "expires_in": 3600})
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

// browser follows the sign-in like a person who clicks allow.
type browser struct{ t *testing.T }

func (b browser) Open(u string) error {
	go func() {
		resp, err := http.Get(u)
		if err != nil {
			b.t.Errorf("browser: %v", err)
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	return nil
}

func TestLoginToAnMCPServerAndRefresh(t *testing.T) {
	f := newFakeServer(t)
	dir := t.TempDir()
	path := StatePath(dir, "work", "notion")
	var out strings.Builder
	if err := Login(context.Background(), secret.OAuth{MCP: f.URL + "/mcp"}, path, browser{t}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state: %v %v", info, err)
	}
	s, err := load(path)
	if err != nil || s.ClientID != "registered-client" || s.Token.RefreshToken != "refresh-1" {
		t.Fatalf("state = %+v, %v", s, err)
	}

	tokens := NewTokens(dir, "work")
	v, err := tokens.Token(context.Background(), "notion", secret.OAuth{})
	if err != nil || string(v.Reveal()) != "access-1" {
		t.Fatalf("token = %q, %v", v.Reveal(), err)
	}

	s.Token.Expiry = time.Now().Add(-time.Minute)
	if err := s.save(path); err != nil {
		t.Fatal(err)
	}
	v, err = NewTokens(dir, "work").Token(context.Background(), "notion", secret.OAuth{})
	if err != nil || string(v.Reveal()) != "access-2" {
		t.Fatalf("refreshed token = %q, %v", v.Reveal(), err)
	}
	if s, _ := load(path); s.Token.RefreshToken != "refresh-2" {
		t.Errorf("a rotated refresh token must be saved: %+v", s.Token)
	}
}

func TestLoginWithAnIssuer(t *testing.T) {
	f := newFakeServer(t)
	path := filepath.Join(t.TempDir(), "google.json")
	if err := Login(context.Background(), secret.OAuth{Issuer: f.URL, ClientID: "my-client", Scopes: []string{"read"}}, path, browser{t}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if s, err := load(path); err != nil || s.ClientID != "my-client" || s.Token.AccessToken != "access-1" {
		t.Fatalf("state = %+v, %v", s, err)
	}
}

func TestTokenWithoutLoginNamesTheCommand(t *testing.T) {
	_, err := NewTokens(t.TempDir(), "work").Token(context.Background(), "notion", secret.OAuth{})
	if err == nil || !strings.Contains(err.Error(), "girdle login --profile work notion") {
		t.Fatalf("err = %v", err)
	}
}
