package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/fnune/doriath/internal/secret"
)

// tokenClient talks to a token endpoint that no metadata describes. It does
// its own requests, because some servers want a JSON body, and want the
// state in the code exchange, which golang.org/x/oauth2 does not send.
type tokenClient struct {
	url      string
	json     bool
	clientID string
	scopes   []string
}

func (c tokenClient) exchange(ctx context.Context, code, verifier, redirect, state string) (*oauth2.Token, error) {
	return c.post(ctx, map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  redirect,
		"client_id":     c.clientID,
		"code_verifier": verifier,
		"state":         state,
	})
}

func (c tokenClient) refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	body := map[string]string{"grant_type": "refresh_token", "refresh_token": refreshToken, "client_id": c.clientID}
	if len(c.scopes) > 0 {
		body["scope"] = strings.Join(c.scopes, " ")
	}
	tok, err := c.post(ctx, body)
	if err != nil {
		return nil, err
	}
	if tok.RefreshToken == "" {
		tok.RefreshToken = refreshToken
	}
	return tok, nil
}

const requestTimeout = 30 * time.Second

func (c tokenClient) post(ctx context.Context, fields map[string]string) (*oauth2.Token, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	var body io.Reader
	contentType := "application/x-www-form-urlencoded"
	if c.json {
		data, err := json.Marshal(fields)
		if err != nil {
			return nil, err
		}
		body, contentType = bytes.NewReader(data), "application/json"
	} else {
		form := url.Values{}
		for k, v := range fields {
			form.Set(k, v)
		}
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token endpoint %s: %w", c.url, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("token endpoint %s: %w", c.url, err)
	}
	var answer struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Error        string `json:"error"`
		Description  string `json:"error_description"`
	}
	decodeErr := json.Unmarshal(data, &answer)
	switch {
	case resp.StatusCode != http.StatusOK && answer.Error != "":
		return nil, fmt.Errorf("token endpoint %s answered %s: %s %s", c.url, resp.Status, answer.Error, answer.Description)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("token endpoint %s answered %s", c.url, resp.Status)
	case decodeErr != nil:
		return nil, fmt.Errorf("token endpoint %s answered with a body that is not JSON: %w", c.url, decodeErr)
	case answer.AccessToken == "":
		return nil, fmt.Errorf("token endpoint %s answered without an access token", c.url)
	}
	tok := &oauth2.Token{AccessToken: answer.AccessToken, RefreshToken: answer.RefreshToken, TokenType: answer.TokenType}
	if tok.TokenType == "" {
		tok.TokenType = "Bearer"
	}
	if answer.ExpiresIn > 0 {
		tok.Expiry = time.Now().Add(time.Duration(answer.ExpiresIn) * time.Second)
	}
	return tok, nil
}

// refreshing is a token source that always asks the token endpoint. It sits
// under oauth2.ReuseTokenSource, which calls it only for an expired token.
type refreshing struct {
	client  tokenClient
	refresh string
}

func (r *refreshing) Token() (*oauth2.Token, error) {
	if r.refresh == "" {
		return nil, errors.New("the login has no refresh token")
	}
	tok, err := r.client.refresh(context.Background(), r.refresh)
	if err != nil {
		return nil, err
	}
	r.refresh = tok.RefreshToken
	return tok, nil
}

func (s State) tokenClient() tokenClient {
	return tokenClient{url: s.TokenURL, json: s.TokenBody == secret.TokenBodyJSON, clientID: s.ClientID, scopes: s.Scopes}
}

// loginExplicit signs in with the endpoints that the profile names. It asks
// no server for metadata. The redirect goes to localhost, the form that such
// servers register for a native app.
func loginExplicit(ctx context.Context, o secret.OAuth, redirect string, fetch authFetcher) (State, error) {
	verifier, state := oauth2.GenerateVerifier(), randomState()
	cfg := &oauth2.Config{ClientID: o.ClientID, Endpoint: oauth2.Endpoint{AuthURL: o.AuthorizeURL, TokenURL: o.TokenURL}, RedirectURL: redirect, Scopes: o.Scopes}
	res, err := fetch(ctx, cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)))
	if err != nil {
		return State{}, err
	}
	if res.State != state {
		return State{}, errors.New("the sign-in answered for another request")
	}
	s := State{ClientID: o.ClientID, AuthURL: o.AuthorizeURL, TokenURL: o.TokenURL, Scopes: o.Scopes, Explicit: true, TokenBody: o.TokenBody}
	tok, err := s.tokenClient().exchange(ctx, res.Code, verifier, redirect, state)
	if err != nil {
		return State{}, err
	}
	s.Token = tok
	return s, nil
}
