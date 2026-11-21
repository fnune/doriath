// Package githubapp mints the installation tokens of a GitHub App. It signs a
// short-lived JWT with the private key of the app, finds the installation on
// the repository, and asks GitHub for a token limited to that repository.
package githubapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fnune/doriath/internal/secret"
)

const (
	defaultAPI = "https://api.github.com"
	// clockSkew backdates the JWT, as GitHub advises, so that a clock a little
	// ahead of GitHub's does not make it invalid.
	clockSkew = 60 * time.Second
	// jwtLifetime stays under the 10 minutes that GitHub allows.
	jwtLifetime = 9 * time.Minute
)

// Minter implements secret.AppTokens for the repository of a session.
type Minter struct {
	HTTP *http.Client
	// API is the base URL of the GitHub API. It is api.github.com when empty.
	API string
	Now func() time.Time
	// Repository is the directory of the session's repository, and Remotes
	// lists the URLs of its remotes, the origin first.
	Repository string
	Remotes    func(ctx context.Context, dir string) ([]string, error)
}

func (m Minter) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m Minter) api() string {
	if m.API != "" {
		return strings.TrimSuffix(m.API, "/")
	}
	return defaultAPI
}

func (m Minter) client() *http.Client {
	if m.HTTP != nil {
		return m.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (m Minter) Mint(ctx context.Context, app secret.GitHubApp, privateKey secret.Value) (secret.Value, time.Time, error) {
	key, err := ParseKey(privateKey.Reveal())
	if err != nil {
		return secret.Value{}, time.Time{}, err
	}
	owner, repos, err := m.targets(ctx, app)
	if err != nil {
		return secret.Value{}, time.Time{}, err
	}
	jwt, err := SignJWT(app.AppID, key, m.now())
	if err != nil {
		return secret.Value{}, time.Time{}, err
	}
	installation, err := m.installation(ctx, jwt, owner, repos[0])
	if err != nil {
		return secret.Value{}, time.Time{}, err
	}
	token, expires, err := m.accessToken(ctx, jwt, installation, owner, repos, app.Permissions)
	if err != nil {
		return secret.Value{}, time.Time{}, err
	}
	return secret.NewValue([]byte(token)), expires, nil
}

// targets is the owner and the repositories that the token reaches.
func (m Minter) targets(ctx context.Context, app secret.GitHubApp) (string, []string, error) {
	if len(app.Repositories) > 0 {
		var owner string
		repos := make([]string, len(app.Repositories))
		for i, r := range app.Repositories {
			owner, repos[i], _ = strings.Cut(r, "/")
		}
		return owner, repos, nil
	}
	if m.Repository == "" || m.Remotes == nil {
		return "", nil, errors.New("the session has no repository, so the token has no repository to reach. Start the session in a git repository with a GitHub remote, or set repositories in github_app")
	}
	urls, err := m.Remotes(ctx, m.Repository)
	if err != nil {
		return "", nil, fmt.Errorf("read the remotes of %s: %w", m.Repository, err)
	}
	for _, u := range urls {
		if owner, repo, ok := ParseRemote(u); ok {
			return owner, []string{repo}, nil
		}
	}
	return "", nil, fmt.Errorf("the repository %s has no GitHub remote, so the token has no repository to reach. Add a remote on github.com, or set repositories in github_app", m.Repository)
}

// SignJWT signs the token that proves to GitHub that you hold the key of the app.
func SignJWT(appID int64, key *rsa.PrivateKey, now time.Time) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iat": now.Add(-clockSkew).Unix(),
		"exp": now.Add(jwtLifetime).Unix(),
		"iss": strconv.FormatInt(appID, 10),
	})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("sign the JWT: %w", err)
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// ParseKey reads the PEM private key that GitHub gives for an app, in the
// PKCS#1 form, or in the PKCS#8 form that some tools write.
func ParseKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(bytes.TrimSpace(data))
	if block == nil {
		return nil, errors.New("the private key of the GitHub App is not in PEM form")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("the private key of the GitHub App is not an RSA key")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("the private key of the GitHub App is not an RSA key")
	}
	return key, nil
}

var (
	httpsRemote = regexp.MustCompile(`^https://(?:[^@/]+@)?github\.com(?::\d+)?/([^/]+)/([^/]+?)(?:\.git)?/?$`)
	sshRemote   = regexp.MustCompile(`^(?:ssh://)?(?:[^@/]+@)?github\.com(?::\d+)?[:/]([^/]+)/([^/]+?)(?:\.git)?/?$`)
)

// ParseRemote reads the owner and the repository from a github.com remote in
// its HTTPS form, https://github.com/owner/repo.git, or its SSH forms,
// git@github.com:owner/repo.git and ssh://git@github.com/owner/repo.git.
func ParseRemote(remote string) (owner, repo string, ok bool) {
	remote = strings.TrimSpace(remote)
	for _, re := range []*regexp.Regexp{httpsRemote, sshRemote} {
		if m := re.FindStringSubmatch(remote); m != nil {
			return m[1], m[2], true
		}
	}
	return "", "", false
}

type apiError struct {
	status  int
	message string
}

func (e *apiError) Error() string { return fmt.Sprintf("GitHub answered %d: %s", e.status, e.message) }

func (m Minter) call(ctx context.Context, jwt, method, path string, body any, out any) error {
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, m.api()+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := m.client().Do(req)
	if err != nil {
		return fmt.Errorf("reach GitHub: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("reach GitHub: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Message == "" {
			e.Message = resp.Status
		}
		return &apiError{status: resp.StatusCode, message: e.Message}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("GitHub answered with a body that is not JSON: %w", err)
	}
	return nil
}

func (m Minter) installation(ctx context.Context, jwt, owner, repo string) (int64, error) {
	var out struct {
		ID int64 `json:"id"`
	}
	err := m.call(ctx, jwt, http.MethodGet, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/installation", nil, &out)
	var api *apiError
	switch {
	case errors.As(err, &api) && api.status == http.StatusUnauthorized:
		return 0, fmt.Errorf("GitHub refused the app's key (%s). Check that app_id and the private key belong to the same app, and that the clock of this machine is right", api.message)
	case errors.As(err, &api) && api.status == http.StatusNotFound:
		return 0, m.notInstalled(ctx, jwt, owner, repo)
	case err != nil:
		return 0, fmt.Errorf("find the installation of the app on %s/%s: %w", owner, repo, err)
	case out.ID == 0:
		return 0, fmt.Errorf("GitHub gave no installation of the app on %s/%s", owner, repo)
	}
	return out.ID, nil
}

func (m Minter) notInstalled(ctx context.Context, jwt, owner, repo string) error {
	msg := fmt.Sprintf("the app is not installed on %s/%s", owner, repo)
	var app struct {
		HTMLURL string `json:"html_url"`
	}
	if m.call(ctx, jwt, http.MethodGet, "/app", nil, &app) == nil && app.HTMLURL != "" {
		msg += ". Install it, and give it access to the repository, at " + strings.TrimSuffix(app.HTMLURL, "/") + "/installations/new"
	}
	return errors.New(msg)
}

func (m Minter) accessToken(ctx context.Context, jwt string, installation int64, owner string, repos []string, permissions map[string]string) (string, time.Time, error) {
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	body := map[string]any{"repositories": repos, "permissions": permissions}
	err := m.call(ctx, jwt, http.MethodPost, "/app/installations/"+strconv.FormatInt(installation, 10)+"/access_tokens", body, &out)
	var api *apiError
	switch {
	case errors.As(err, &api) && api.status == http.StatusUnprocessableEntity:
		return "", time.Time{}, fmt.Errorf("GitHub refused the token for %s: %s. Check that the app has these permissions and that its installation allows them", strings.Join(repos, ", "), api.message)
	case err != nil:
		return "", time.Time{}, fmt.Errorf("mint a token on %s: %w", owner, err)
	case out.Token == "" || out.ExpiresAt.IsZero():
		return "", time.Time{}, errors.New("GitHub answered without a token or its expiry")
	}
	return out.Token, out.ExpiresAt, nil
}
