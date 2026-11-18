// Package oauth signs in to OAuth servers on the host and keeps their tokens
// there. doriath profiles login runs the browser flow once; sessions then get fresh
// access tokens from here, which the proxy adds to requests, so no token
// ever reaches the jail.
package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"

	"github.com/fnune/doriath/internal/cli"
	"github.com/fnune/doriath/internal/secret"
)

type State struct {
	ClientID        string        `json:"client_id"`
	ClientSecret    string        `json:"client_secret,omitempty"`
	AuthURL         string        `json:"auth_url"`
	TokenURL        string        `json:"token_url"`
	RegistrationURL string        `json:"registration_url,omitempty"`
	Scopes          []string      `json:"scopes,omitempty"`
	Token           *oauth2.Token `json:"token"`
}

func (s State) config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.ClientID,
		ClientSecret: s.ClientSecret,
		Endpoint:     oauth2.Endpoint{AuthURL: s.AuthURL, TokenURL: s.TokenURL},
		Scopes:       s.Scopes,
	}
}

func StatePath(stateDir, profile, name string) string {
	return filepath.Join(stateDir, "oauth", profile, name+".json")
}

func load(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, fmt.Errorf("%s: %w", path, err)
	}
	if s.Token == nil {
		return State{}, fmt.Errorf("%s: no token", path)
	}
	return s, nil
}

func (s State) save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type Tokens struct {
	stateDir string
	owner    func(secret string) string

	mu      sync.Mutex
	sources map[string]oauth2.TokenSource
}

func NewTokens(stateDir, profile string) *Tokens {
	return NewTokensOwnedBy(stateDir, func(string) string { return profile })
}

func NewTokensOwnedBy(stateDir string, owner func(secret string) string) *Tokens {
	return &Tokens{stateDir: stateDir, owner: owner, sources: map[string]oauth2.TokenSource{}}
}

func (t *Tokens) Token(_ context.Context, name string, _ secret.OAuth) (secret.Value, error) {
	t.mu.Lock()
	src, ok := t.sources[name]
	if !ok {
		profile := t.owner(name)
		path := StatePath(t.stateDir, profile, name)
		s, err := load(path)
		if errors.Is(err, os.ErrNotExist) {
			t.mu.Unlock()
			return secret.Value{}, fmt.Errorf("secret %q: not signed in: run %s", name, cli.Code(cli.Line("profiles", "login", profile, name)))
		}
		if err != nil {
			t.mu.Unlock()
			return secret.Value{}, fmt.Errorf("secret %q: %w", name, err)
		}
		src = oauth2.ReuseTokenSource(s.Token, &saving{src: s.config().TokenSource(context.Background(), s.Token), state: s, path: path})
		t.sources[name] = src
	}
	t.mu.Unlock()
	tok, err := src.Token()
	if err != nil {
		return secret.Value{}, fmt.Errorf("secret %q: refresh the login: %w; run %s again", name, err, cli.Code(cli.Line("profiles", "login", t.owner(name), name)))
	}
	return secret.NewValue([]byte(tok.AccessToken)), nil
}

type saving struct {
	src   oauth2.TokenSource
	state State
	path  string
}

func (s *saving) Token() (*oauth2.Token, error) {
	tok, err := s.src.Token()
	if err != nil {
		return nil, err
	}
	s.state.Token = tok
	return tok, s.state.save(s.path)
}

type Browser interface {
	Open(url string) error
}

// Login signs in for one OAuth secret and saves the result at path. The
// server redirects your browser back to a listener on the host's loopback
// address, which the jail cannot reach.
func Login(ctx context.Context, o secret.OAuth, path string, browser Browser, w io.Writer) error {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer l.Close()
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", l.Addr().(*net.TCPAddr).Port)
	fetch := func(ctx context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
		fmt.Fprintf(w, "Sign in at:\n  %s\n", args.URL)
		if err := browser.Open(args.URL); err != nil {
			fmt.Fprintln(w, "Open it in your browser on this machine.")
		}
		return awaitCallback(ctx, l)
	}
	var s State
	if o.MCP != "" {
		s, err = loginMCP(ctx, o.MCP, redirect, fetch)
	} else {
		s, err = loginIssuer(ctx, o, redirect, fetch)
	}
	if err != nil {
		return err
	}
	if s.Token.RefreshToken == "" {
		fmt.Fprintln(w, "The server gave no refresh token, so you sign in again when this one expires.")
	}
	return s.save(path)
}

func loginMCP(ctx context.Context, server, redirect string, fetch auth.AuthorizationCodeFetcher) (State, error) {
	var s State
	handler, err := auth.NewAuthorizationCodeHandler(&auth.AuthorizationCodeHandlerConfig{
		DynamicClientRegistrationConfig: &auth.DynamicClientRegistrationConfig{Metadata: &oauthex.ClientRegistrationMetadata{
			ClientName:              "doriath",
			RedirectURIs:            []string{redirect},
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			ResponseTypes:           []string{"code"},
			TokenEndpointAuthMethod: "none",
		}},
		RedirectURL:              redirect,
		AuthorizationCodeFetcher: fetch,
		RequestRefreshToken:      true,
		NewTokenSource: func(ctx context.Context, c *oauth2.Config, tok *oauth2.Token) (oauth2.TokenSource, error) {
			s = State{ClientID: c.ClientID, ClientSecret: c.ClientSecret, AuthURL: c.Endpoint.AuthURL, TokenURL: c.Endpoint.TokenURL, Scopes: c.Scopes, Token: tok}
			return c.TokenSource(ctx, tok), nil
		},
	})
	if err != nil {
		return State{}, err
	}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"doriath","version":"0"}}}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server, bytes.NewReader(body))
	if err != nil {
		return State{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return State{}, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		_ = resp.Body.Close()
		return State{}, fmt.Errorf("%s answered %s, not 401: it does not ask for a login", server, resp.Status)
	}
	if err := handler.Authorize(ctx, req, resp); err != nil {
		return State{}, err
	}
	if s.Token == nil {
		return State{}, errors.New("the login finished without a token")
	}
	if u, err := url.Parse(s.TokenURL); err == nil {
		if meta, err := auth.GetAuthServerMetadata(ctx, u.Scheme+"://"+u.Host, http.DefaultClient); err == nil && meta != nil {
			s.RegistrationURL = meta.RegistrationEndpoint
		}
	}
	return s, nil
}

func Endpoints(stateDir, profile, name string) (token, registration string, ok bool) {
	s, err := load(StatePath(stateDir, profile, name))
	if err != nil {
		return "", "", false
	}
	return s.TokenURL, s.RegistrationURL, true
}

func loginIssuer(ctx context.Context, o secret.OAuth, redirect string, fetch auth.AuthorizationCodeFetcher) (State, error) {
	meta, err := auth.GetAuthServerMetadata(ctx, o.Issuer, http.DefaultClient)
	if err != nil {
		return State{}, err
	}
	if meta == nil {
		return State{}, fmt.Errorf("%s publishes no OAuth metadata", o.Issuer)
	}
	cfg := &oauth2.Config{
		ClientID:    o.ClientID,
		Endpoint:    oauth2.Endpoint{AuthURL: meta.AuthorizationEndpoint, TokenURL: meta.TokenEndpoint},
		RedirectURL: redirect,
		Scopes:      o.Scopes,
	}
	verifier, state := oauth2.GenerateVerifier(), randomState()
	res, err := fetch(ctx, &auth.AuthorizationArgs{URL: cfg.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))})
	if err != nil {
		return State{}, err
	}
	if res.State != state {
		return State{}, errors.New("the sign-in answered for another request")
	}
	tok, err := cfg.Exchange(ctx, res.Code, oauth2.VerifierOption(verifier))
	if err != nil {
		return State{}, err
	}
	return State{ClientID: o.ClientID, AuthURL: cfg.Endpoint.AuthURL, TokenURL: cfg.Endpoint.TokenURL, RegistrationURL: meta.RegistrationEndpoint, Scopes: o.Scopes, Token: tok}, nil
}

func randomState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

const loginTimeout = 5 * time.Minute

func awaitCallback(ctx context.Context, l net.Listener) (*auth.AuthorizationResult, error) {
	ctx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()
	results := make(chan *auth.AuthorizationResult, 1)
	failures := make(chan error, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			fmt.Fprintln(w, "Sign-in failed. You can close this tab.")
			failures <- fmt.Errorf("the server refused the sign-in: %s %s", e, q.Get("error_description"))
			return
		}
		fmt.Fprintln(w, "Signed in. You can close this tab.")
		results <- &auth.AuthorizationResult{Code: q.Get("code"), State: q.Get("state"), Iss: q.Get("iss")}
	})}
	go func() { _ = srv.Serve(l) }()

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	select {
	case r := <-results:
		return r, nil
	case err := <-failures:
		return nil, err
	case <-ctx.Done():
		return nil, errors.New("no sign-in arrived within 5 minutes")
	}
}
