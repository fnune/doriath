package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/keyringtest"
	"github.com/fnune/doriath/internal/secret"
)

// explicitServer is an authorization server that publishes no metadata. Its
// token endpoint takes a JSON body, as the one of Claude Code's login does.
type explicitServer struct {
	*httptest.Server
	mu sync.Mutex

	discovery  int
	authorize  url.Values
	requests   []tokenRequest
	exchange   func(w http.ResponseWriter)
	refresh    func(w http.ResponseWriter)
	rotateFrom string
}

type tokenRequest struct {
	contentType string
	fields      map[string]string
}

func newExplicitServer(t *testing.T) *explicitServer {
	t.Helper()
	f := &explicitServer{rotateFrom: "refresh-1"}
	mux := http.NewServeMux()
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	mux.HandleFunc("/.well-known/", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		f.discovery++
		f.mu.Unlock()
		http.NotFound(w, nil)
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		f.authorize = q
		f.mu.Unlock()
		back, _ := url.Parse(q.Get("redirect_uri"))
		back.RawQuery = url.Values{"code": {"the-code"}, "state": {q.Get("state")}}.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		req := tokenRequest{contentType: r.Header.Get("Content-Type"), fields: map[string]string{}}
		if strings.HasPrefix(req.contentType, "application/json") {
			_ = json.NewDecoder(r.Body).Decode(&req.fields)
		} else {
			_ = r.ParseForm()
			for k := range r.Form {
				req.fields[k] = r.Form.Get(k)
			}
		}
		f.mu.Lock()
		f.requests = append(f.requests, req)
		exchange, refresh, rotateFrom := f.exchange, f.refresh, f.rotateFrom
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch req.fields["grant_type"] {
		case "authorization_code":
			if exchange != nil {
				exchange(w)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-1", "refresh_token": "refresh-1", "token_type": "Bearer", "expires_in": 3600})
		case "refresh_token":
			if refresh != nil {
				refresh(w)
				return
			}
			if req.fields["refresh_token"] != rotateFrom {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-2", "refresh_token": "refresh-2", "expires_in": 3600})
		}
	})
	return f
}

func (f *explicitServer) oauth(body string) secret.OAuth {
	return secret.OAuth{AuthorizeURL: f.URL + "/authorize", TokenURL: f.URL + "/token", TokenBody: body, ClientID: "the-client", Scopes: []string{"user:inference", "user:profile"}}
}

func (f *explicitServer) lastRequest() tokenRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[len(f.requests)-1]
}

func (f *explicitServer) tokenRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func answerWith(code, state string) callbackBrowser {
	return callbackBrowser{answer: func(signIn url.Values) url.Values {
		if state == "" {
			state = signIn.Get("state")
		}
		return url.Values{"code": {code}, "state": {state}}
	}}
}

func TestAnExplicitLoginAsksNoMetadataAndSendsWhatThePageNeeds(t *testing.T) {
	for name, body := range map[string]string{"json": secret.TokenBodyJSON, "form": ""} {
		t.Run(name, func(t *testing.T) {
			f := newExplicitServer(t)
			logins := keyringtest.New()
			if err := Login(context.Background(), f.oauth(body), logins, "work", "claude", browser{t}, io.Discard); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			discovery, q := f.discovery, f.authorize
			f.mu.Unlock()
			if discovery != 0 {
				t.Errorf("an explicit login asked for metadata %d times", discovery)
			}
			if q.Get("client_id") != "the-client" || q.Get("response_type") != "code" || q.Get("scope") != "user:inference user:profile" {
				t.Errorf("authorize query = %v", q)
			}
			if !strings.HasPrefix(q.Get("redirect_uri"), "http://localhost:") || !strings.HasSuffix(q.Get("redirect_uri"), "/callback") {
				t.Errorf("redirect_uri = %q", q.Get("redirect_uri"))
			}
			req := f.lastRequest()
			wantType := "application/x-www-form-urlencoded"
			if body == secret.TokenBodyJSON {
				wantType = "application/json"
			}
			if req.contentType != wantType {
				t.Errorf("content type = %q, want %q", req.contentType, wantType)
			}
			sum := sha256.Sum256([]byte(req.fields["code_verifier"]))
			if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) {
				t.Errorf("the challenge %q does not match the verifier %q", q.Get("code_challenge"), req.fields["code_verifier"])
			}
			if req.fields["state"] != q.Get("state") || req.fields["code"] != "the-code" || req.fields["redirect_uri"] != q.Get("redirect_uri") || req.fields["client_id"] != "the-client" {
				t.Errorf("exchange = %v", req.fields)
			}
			v, err := NewTokens(logins, "work").Token(context.Background(), "claude", secret.OAuth{})
			if err != nil || string(v.Reveal()) != "access-1" {
				t.Fatalf("token = %q, %v", v.Reveal(), err)
			}
		})
	}
}

func TestAnExplicitLoginRefreshesAndWritesTheRotatedTokenBack(t *testing.T) {
	f := newExplicitServer(t)
	logins := keyringtest.New()
	if err := Login(context.Background(), f.oauth(secret.TokenBodyJSON), logins, "work", "claude", browser{t}, io.Discard); err != nil {
		t.Fatal(err)
	}
	expire := func() {
		s, err := load(logins, "work", "claude")
		if err != nil {
			t.Fatal(err)
		}
		s.Token.Expiry = time.Now().Add(-time.Minute)
		if err := s.save(logins, "work", "claude"); err != nil {
			t.Fatal(err)
		}
	}
	expire()
	v, err := NewTokens(logins, "work").Token(context.Background(), "claude", secret.OAuth{})
	if err != nil || string(v.Reveal()) != "access-2" {
		t.Fatalf("refreshed token = %q, %v", v.Reveal(), err)
	}
	req := f.lastRequest()
	if req.contentType != "application/json" || req.fields["refresh_token"] != "refresh-1" || req.fields["client_id"] != "the-client" || req.fields["scope"] != "user:inference user:profile" {
		t.Errorf("refresh request = %+v", req)
	}
	if s, _ := load(logins, "work", "claude"); s.Token.RefreshToken != "refresh-2" || s.Token.AccessToken != "access-2" {
		t.Errorf("the keyring holds %+v", s.Token)
	}
	f.mu.Lock()
	f.rotateFrom = "refresh-2"
	f.mu.Unlock()
	expire()
	if v, err := NewTokens(logins, "work").Token(context.Background(), "claude", secret.OAuth{}); err != nil || string(v.Reveal()) != "access-2" {
		t.Errorf("a refresh with the rotated token = %q, %v", v.Reveal(), err)
	}
}

func TestAFailedRefreshLeavesTheStoredLoginAlone(t *testing.T) {
	for name, answer := range map[string]func(http.ResponseWriter){
		"revoked": func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"revoked"}`))
		},
		"server error": func(w http.ResponseWriter) { w.WriteHeader(http.StatusBadGateway) },
		"not JSON":     func(w http.ResponseWriter) { _, _ = w.Write([]byte("<html>")) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newExplicitServer(t)
			logins := keyringtest.New()
			if err := Login(context.Background(), f.oauth(secret.TokenBodyJSON), logins, "work", "claude", browser{t}, io.Discard); err != nil {
				t.Fatal(err)
			}
			s, _ := load(logins, "work", "claude")
			s.Token.Expiry = time.Now().Add(-time.Minute)
			if err := s.save(logins, "work", "claude"); err != nil {
				t.Fatal(err)
			}
			before, _ := logins.Read("work", "claude")
			f.mu.Lock()
			f.refresh = answer
			f.mu.Unlock()
			_, err := NewTokens(logins, "work").Token(context.Background(), "claude", secret.OAuth{})
			if err == nil || !strings.Contains(err.Error(), "refresh the login") || !strings.Contains(err.Error(), "doriath profiles login work claude") {
				t.Fatalf("err = %v", err)
			}
			if after, _ := logins.Read("work", "claude"); string(after.Reveal()) != string(before.Reveal()) {
				t.Errorf("a failed refresh changed the login:\n%s\n%s", before.Reveal(), after.Reveal())
			}
		})
	}
}

func TestAnExplicitLoginStoresNothingWhenTheTokenEndpointFails(t *testing.T) {
	for name, c := range map[string]struct {
		answer func(http.ResponseWriter)
		want   string
	}{
		"oauth error": {func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"the code expired"}`))
		}, "answered 400 Bad Request: invalid_grant the code expired"},
		"error without a body": {func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }, "answered 500 Internal Server Error"},
		"unavailable":          {func(w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) }, "answered 503 Service Unavailable"},
		"malformed JSON":       {func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"access_token":`)) }, "a body that is not JSON"},
		"no access token":      {func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"refresh_token":"r"}`)) }, "without an access token"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newExplicitServer(t)
			f.exchange = c.answer
			logins := keyringtest.New()
			err := Login(context.Background(), f.oauth(secret.TokenBodyJSON), logins, "work", "claude", browser{t}, io.Discard)
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), f.URL+"/token") {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if logins.Has("work", "claude") {
				t.Error("a failed sign-in stored a login")
			}
		})
	}
}

func TestAnExplicitLoginRefusesAnAnswerForAnotherRequest(t *testing.T) {
	f := newExplicitServer(t)
	logins := keyringtest.New()
	b := answerWith("the-code", "another")
	b.t = t
	err := Login(context.Background(), f.oauth(secret.TokenBodyJSON), logins, "work", "claude", b, io.Discard)
	if err == nil || err.Error() != "the sign-in answered for another request" {
		t.Fatalf("err = %v", err)
	}
	if f.tokenRequests() != 0 || logins.Has("work", "claude") {
		t.Error("a code from another request was used")
	}
}

func expireLogin(t *testing.T, logins secret.Keyring) {
	t.Helper()
	s, err := load(logins, "work", "claude")
	if err != nil {
		t.Fatal(err)
	}
	s.Token.Expiry = time.Now().Add(-time.Minute)
	if err := s.save(logins, "work", "claude"); err != nil {
		t.Fatal(err)
	}
}

func TestTwoStoresThatShareALoginUseTheTokenThatTheFirstRefreshWrote(t *testing.T) {
	f := newExplicitServer(t)
	logins := keyringtest.New()
	if err := Login(context.Background(), f.oauth(secret.TokenBodyJSON), logins, "work", "claude", browser{t}, io.Discard); err != nil {
		t.Fatal(err)
	}
	first, second := NewTokens(logins, "work"), NewTokens(logins, "work")
	if _, err := second.Token(context.Background(), "claude", secret.OAuth{}); err != nil {
		t.Fatal(err)
	}
	expireLogin(t, logins)
	// The second store holds the old token in memory, and it has expired too.
	second.cached["claude"].Expiry = time.Now().Add(-time.Minute)
	v, err := first.Token(context.Background(), "claude", secret.OAuth{})
	if err != nil || string(v.Reveal()) != "access-2" {
		t.Fatalf("first = %q, %v", v.Reveal(), err)
	}
	// A refresh with the old refresh token fails now, as it does at Anthropic.
	f.mu.Lock()
	f.rotateFrom = "refresh-2"
	before := len(f.requests)
	f.mu.Unlock()
	v, err = second.Token(context.Background(), "claude", secret.OAuth{})
	if err != nil || string(v.Reveal()) != "access-2" {
		t.Fatalf("second = %q, %v", v.Reveal(), err)
	}
	if f.tokenRequests() != before {
		t.Errorf("the second store refreshed again: %d requests", f.tokenRequests()-before)
	}
}

func TestARejectedTokenMakesTheNextCallUseANewerOneOrRefresh(t *testing.T) {
	f := newExplicitServer(t)
	logins := keyringtest.New()
	if err := Login(context.Background(), f.oauth(secret.TokenBodyJSON), logins, "work", "claude", browser{t}, io.Discard); err != nil {
		t.Fatal(err)
	}
	a, b := NewTokens(logins, "work"), NewTokens(logins, "work")
	for _, tk := range []*Tokens{a, b} {
		if v, err := tk.Token(context.Background(), "claude", secret.OAuth{}); err != nil || string(v.Reveal()) != "access-1" {
			t.Fatalf("%q, %v", v.Reveal(), err)
		}
	}
	// The server refuses access-1 in both stores. A refreshes, and B finds A's token.
	a.Reject("claude", "access-1")
	if v, err := a.Token(context.Background(), "claude", secret.OAuth{}); err != nil || string(v.Reveal()) != "access-2" {
		t.Fatalf("a = %q, %v", v.Reveal(), err)
	}
	b.Reject("claude", "access-1")
	before := f.tokenRequests()
	if v, err := b.Token(context.Background(), "claude", secret.OAuth{}); err != nil || string(v.Reveal()) != "access-2" {
		t.Fatalf("b = %q, %v", v.Reveal(), err)
	}
	if f.tokenRequests() != before {
		t.Error("b asked the server although the keyring had a newer token")
	}
	b.Reject("claude", "some other token")
	if v, _ := b.Token(context.Background(), "claude", secret.OAuth{}); string(v.Reveal()) != "access-2" {
		t.Errorf("a rejection of another token changed the answer: %q", v.Reveal())
	}
}

func TestStoresInOneFolderRefreshOneAtATime(t *testing.T) {
	f := newExplicitServer(t)
	logins := keyringtest.New()
	if err := Login(context.Background(), f.oauth(secret.TokenBodyJSON), logins, "work", "claude", browser{t}, io.Discard); err != nil {
		t.Fatal(err)
	}
	expireLogin(t, logins)
	dir := t.TempDir()
	before := f.tokenRequests()
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := NewTokens(logins, "work").WithLockDir(dir).Token(context.Background(), "claude", secret.OAuth{})
			if err != nil || string(v.Reveal()) != "access-2" {
				t.Errorf("token = %q, %v", v.Reveal(), err)
			}
		}()
	}
	wg.Wait()
	if n := f.tokenRequests() - before; n != 1 {
		t.Errorf("%d refreshes, want 1", n)
	}
}
