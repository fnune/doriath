// Package oauth signs in to OAuth servers on the host and keeps their tokens
// in the keyring of your desktop. doriath profiles login runs the browser flow once; sessions then get fresh
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
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"

	"github.com/fnune/doriath/internal/cli"
	"github.com/fnune/doriath/internal/secret"
)

type State struct {
	ClientID        string   `json:"client_id"`
	ClientSecret    string   `json:"client_secret,omitempty"`
	AuthURL         string   `json:"auth_url"`
	TokenURL        string   `json:"token_url"`
	RegistrationURL string   `json:"registration_url,omitempty"`
	Scopes          []string `json:"scopes,omitempty"`
	// Explicit marks a login to endpoints that the profile names, which
	// tokenClient serves. TokenBody is how that endpoint wants requests.
	Explicit  bool          `json:"explicit,omitempty"`
	TokenBody string        `json:"token_body,omitempty"`
	Token     *oauth2.Token `json:"token"`
}

func (s State) config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.ClientID,
		ClientSecret: s.ClientSecret,
		Endpoint:     oauth2.Endpoint{AuthURL: s.AuthURL, TokenURL: s.TokenURL},
		Scopes:       s.Scopes,
	}
}

func load(v secret.Keyring, profile, name string) (State, error) {
	value, err := v.Read(profile, name)
	if err != nil {
		return State{}, err
	}
	var s State
	if err := json.Unmarshal(value.Reveal(), &s); err != nil {
		return State{}, fmt.Errorf("login %s/%s in the keyring: %w", profile, name, err)
	}
	if s.Token == nil {
		return State{}, fmt.Errorf("login %s/%s in the keyring: no token", profile, name)
	}
	return s, nil
}

func (s State) save(v secret.Keyring, profile, name string) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return v.Write(profile, name, secret.NewValue(data))
}

// SignedIn tells whether the keyring holds a login for the secret.
func SignedIn(v secret.Keyring, profile, name string) bool {
	_, err := load(v, profile, name)
	return err == nil
}

// Tokens serves the access tokens of logins in the keyring. Several sessions,
// and several programs, share one login, and a server that rotates refresh
// tokens kills the old pair of whoever refreshed before. So a Tokens value
// keeps no refresh token of its own: it reads the keyring before it refreshes,
// takes a lock that other processes take too, and uses a token that another
// process wrote in the meantime.
type Tokens struct {
	logins  secret.Keyring
	owner   func(secret string) string
	target  func(secret string) string
	lockDir string
	now     func() time.Time

	mu       sync.Mutex
	cached   map[string]*oauth2.Token
	rejected map[string]string
}

func NewTokens(logins secret.Keyring, profile string) *Tokens {
	return NewTokensOwnedBy(logins, func(string) string { return profile })
}

func NewTokensOwnedBy(logins secret.Keyring, owner func(secret string) string) *Tokens {
	return &Tokens{logins: logins, owner: owner, target: owner, now: time.Now, cached: map[string]*oauth2.Token{}, rejected: map[string]string{}}
}

// WithLoginProfile sets the profile that the messages name in the command to
// sign in again, when it is not the owner of the login: a login that a
// module gives belongs to every profile with the module.
func (t *Tokens) WithLoginProfile(target func(secret string) string) *Tokens {
	t.target = target
	return t
}

// WithLockDir sets the folder for the lock files that keep processes from
// refreshing one login at the same time. Without it, only this value refreshes
// under a lock.
func (t *Tokens) WithLockDir(dir string) *Tokens {
	t.lockDir = dir
	return t
}

func (t *Tokens) notSignedIn(name string) error {
	return fmt.Errorf("secret %q: not signed in: run %s", name, cli.Code(cli.Line("profiles", "login", t.target(name), name)))
}

func (t *Tokens) usable(tok *oauth2.Token, name string) bool {
	return tok != nil && tok.Valid() && tok.AccessToken != t.rejected[name]
}

func (t *Tokens) Token(ctx context.Context, name string, _ secret.OAuth) (secret.Value, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if tok := t.cached[name]; t.usable(tok, name) {
		return secret.NewValue([]byte(tok.AccessToken)), nil
	}
	profile := t.owner(name)
	unlock, err := t.lock(profile, name)
	if err != nil {
		return secret.Value{}, fmt.Errorf("secret %q: %w", name, err)
	}
	defer unlock()
	s, err := load(t.logins, profile, name)
	if errors.Is(err, secret.ErrNotInKeyring) {
		return secret.Value{}, t.notSignedIn(name)
	}
	if err != nil {
		return secret.Value{}, fmt.Errorf("secret %q: %w", name, err)
	}
	if t.usable(s.Token, name) {
		t.cached[name] = s.Token
		return secret.NewValue([]byte(s.Token.AccessToken)), nil
	}
	tok, err := s.refresh(ctx)
	if err != nil {
		return secret.Value{}, fmt.Errorf("secret %q: refresh the login: %w; run %s again", name, err, cli.Code(cli.Line("profiles", "login", t.target(name), name)))
	}
	s.Token = tok
	if err := s.save(t.logins, profile, name); err != nil {
		return secret.Value{}, fmt.Errorf("secret %q: keep the refreshed login: %w", name, err)
	}
	delete(t.rejected, name)
	t.cached[name] = tok
	return secret.NewValue([]byte(tok.AccessToken)), nil
}

// Reject says that a server refused this access token. The next call reads
// the keyring for a newer token that another process wrote, and refreshes if
// there is none.
func (t *Tokens) Reject(name, accessToken string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if tok := t.cached[name]; tok != nil && tok.AccessToken == accessToken {
		delete(t.cached, name)
	}
	t.rejected[name] = accessToken
}

// refresh asks the token endpoint for a new token with the refresh token of
// the login in the keyring, whatever the expiry says.
func (s State) refresh(ctx context.Context) (*oauth2.Token, error) {
	if s.Token.RefreshToken == "" {
		return nil, errors.New("the login has no refresh token")
	}
	if s.Explicit {
		return s.tokenClient().refresh(ctx, s.Token.RefreshToken)
	}
	expired := *s.Token
	expired.Expiry = time.Now().Add(-time.Hour)
	return s.config().TokenSource(ctx, &expired).Token()
}

// Migrate moves the login files of earlier versions into the keyring and
// deletes them. A login that the keyring already holds is newer than its
// file, so only the file goes. A file stays when the keyring does not answer.
func Migrate(stateDir string, logins secret.Keyring) error {
	root := filepath.Join(stateDir, "oauth")
	profiles, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, dir := range profiles {
		profile := dir.Name()
		files, err := os.ReadDir(filepath.Join(root, profile))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, f := range files {
			path := filepath.Join(root, profile, f.Name())
			name, isLogin := strings.CutSuffix(f.Name(), ".json")
			if !isLogin {
				errs = append(errs, os.Remove(path))
				continue
			}
			errs = append(errs, moveLogin(path, logins, profile, name))
		}
		_ = os.Remove(filepath.Join(root, profile))
	}
	_ = os.Remove(root)
	return errors.Join(errs...)
}

func moveLogin(path string, logins secret.Keyring, profile, name string) error {
	_, err := logins.Read(profile, name)
	switch {
	case err == nil:
		return os.Remove(path)
	case !errors.Is(err, secret.ErrNotInKeyring):
		return fmt.Errorf("keep %s: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil || s.Token == nil {
		return fmt.Errorf("keep %s: it holds no login", path)
	}
	if err := logins.Write(profile, name, secret.NewValue(data)); err != nil {
		return fmt.Errorf("keep %s: %w", path, err)
	}
	return os.Remove(path)
}

// authFetcher sends you to the sign-in page and returns what the redirect carries.
type authFetcher func(ctx context.Context, signIn string) (*auth.AuthorizationResult, error)

type Browser interface {
	Open(url string) error
}

// Login signs in for one OAuth secret and saves the result in the keyring. The
// server redirects your browser back to a listener on the host's loopback
// address, which the jail cannot reach.
func Login(ctx context.Context, o secret.OAuth, logins secret.Keyring, profile, name string, browser Browser, w io.Writer) error {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer l.Close()
	host := "127.0.0.1"
	if o.Explicit() {
		host = "localhost"
	}
	redirect := fmt.Sprintf("http://%s:%d/callback", host, l.Addr().(*net.TCPAddr).Port)
	fetchURL := func(ctx context.Context, signIn string) (*auth.AuthorizationResult, error) {
		fmt.Fprintf(w, "Sign in at:\n  %s\n", signIn)
		if err := browser.Open(signIn); err != nil {
			fmt.Fprintln(w, "Open it in your browser on this machine.")
		}
		return awaitCallback(ctx, l)
	}
	fetch := func(ctx context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
		return fetchURL(ctx, args.URL)
	}
	var s State
	switch {
	case o.Explicit():
		s, err = loginExplicit(ctx, o, redirect, fetchURL)
	case o.MCP != "":
		s, err = loginMCP(ctx, o.MCP, redirect, fetch)
	default:
		s, err = loginIssuer(ctx, o, redirect, fetch)
	}
	if err != nil {
		return err
	}
	if s.Token.RefreshToken == "" {
		fmt.Fprintln(w, "The server gave no refresh token, so you sign in again when this one expires.")
	}
	return s.save(logins, profile, name)
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

func Endpoints(logins secret.Keyring, profile, name string) (token, registration string, ok bool) {
	s, err := load(logins, profile, name)
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
