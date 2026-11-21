package githubapp

import (
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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/secret"
)

var now = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func newKey(t *testing.T) (*rsa.PrivateKey, secret.Value) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key, secret.NewValue(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

type fakeGitHub struct {
	*httptest.Server
	key *rsa.PrivateKey

	mu       sync.Mutex
	requests []string
	tokenReq map[string]any
	// installations maps owner/repo to an installation ID.
	installations map[string]int64
	tokenStatus   int
	expires       time.Time
}

func newFakeGitHub(t *testing.T, key *rsa.PrivateKey) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{key: key, installations: map[string]int64{"fnune/doriath": 42}, expires: now.Add(time.Hour)}
	mux := http.NewServeMux()
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		if err := f.checkJWT(r); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"` + err.Error() + `"}`))
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.Close)
	mux.HandleFunc("GET /repos/{owner}/{repo}/installation", func(w http.ResponseWriter, r *http.Request) {
		id, ok := f.installations[r.PathValue("owner")+"/"+r.PathValue("repo")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]int64{"id": id})
	})
	mux.HandleFunc("GET /app", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"html_url": "https://github.com/apps/fnune-agents"})
	})
	mux.HandleFunc("POST /app/installations/{id}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewDecoder(r.Body).Decode(&f.tokenReq)
		if f.tokenStatus != 0 {
			w.WriteHeader(f.tokenStatus)
			_, _ = w.Write([]byte(`{"message":"The permissions requested are not granted to this installation."}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_installation-" + r.PathValue("id"), "expires_at": f.expires.Format(time.RFC3339)})
	})
	return f
}

// checkJWT verifies the signature with the public key, and the claims that
// GitHub requires: a start in the past and an end under ten minutes ahead.
func (f *fakeGitHub) checkJWT(r *http.Request) error {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(token, ".")
	if !ok || len(parts) != 3 {
		return errors.New("A JSON web token could not be decoded")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return errors.New("A JSON web token could not be decoded")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&f.key.PublicKey, crypto.SHA256, sum[:], signature) != nil {
		return errors.New("Bad credentials")
	}
	return nil
}

func (f *fakeGitHub) minter(remotes ...string) Minter {
	return Minter{API: f.URL, Now: func() time.Time { return now }, Repository: "/work/doriath", Remotes: func(context.Context, string) ([]string, error) { return remotes, nil }}
}

func (f *fakeGitHub) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

var app = secret.GitHubApp{AppID: 123456, Key: "key", Permissions: map[string]string{"contents": "write", "pull_requests": "write"}}

func TestTheTokenIsLimitedToTheRepositoryOfTheSession(t *testing.T) {
	key, pemKey := newKey(t)
	f := newFakeGitHub(t, key)
	v, expires, err := f.minter("https://github.com/fnune/doriath.git").Mint(context.Background(), app, pemKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(v.Reveal()) != "ghs_installation-42" || !expires.Equal(now.Add(time.Hour)) {
		t.Errorf("token %q, expires %v", v.Reveal(), expires)
	}
	if got := strings.Join(f.paths(), ", "); got != "GET /repos/fnune/doriath/installation, POST /app/installations/42/access_tokens" {
		t.Errorf("requests = %s", got)
	}
	repos, _ := f.tokenReq["repositories"].([]any)
	perms, _ := f.tokenReq["permissions"].(map[string]any)
	if len(repos) != 1 || repos[0] != "doriath" || len(perms) != 2 || perms["contents"] != "write" || perms["pull_requests"] != "write" {
		t.Errorf("token request = %v", f.tokenReq)
	}
}

func TestTheJWTHasTheClaimsAndTheSignatureThatGitHubChecks(t *testing.T) {
	key, _ := newKey(t)
	token, err := SignJWT(123456, key, now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	var header map[string]string
	var claims map[string]any
	for i, into := range []any{&header, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil || json.Unmarshal(raw, into) != nil {
			t.Fatalf("part %d: %v", i, err)
		}
	}
	if header["alg"] != "RS256" || header["typ"] != "JWT" {
		t.Errorf("header = %v", header)
	}
	iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
	if iat != now.Add(-60*time.Second).Unix() || exp-now.Unix() >= 600 || exp <= now.Unix() || claims["iss"] != "123456" {
		t.Errorf("claims = %v", claims)
	}
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], signature); err != nil {
		t.Errorf("signature: %v", err)
	}
}

func TestAKeyThatDoesNotBelongToTheAppIsRefused(t *testing.T) {
	key, _ := newKey(t)
	_, other := newKey(t)
	f := newFakeGitHub(t, key)
	_, _, err := f.minter("https://github.com/fnune/doriath").Mint(context.Background(), app, other)
	if err == nil || !strings.Contains(err.Error(), "GitHub refused the app's key") || !strings.Contains(err.Error(), "app_id") {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := f.minter("https://github.com/fnune/doriath").Mint(context.Background(), app, secret.NewValue([]byte("not a key"))); err == nil || !strings.Contains(err.Error(), "not in PEM form") {
		t.Errorf("a value that is no key: %v", err)
	}
}

func TestWithoutAnInstallationTheErrorGivesTheInstallURL(t *testing.T) {
	key, pemKey := newKey(t)
	f := newFakeGitHub(t, key)
	_, _, err := f.minter("git@github.com:fnune/other.git").Mint(context.Background(), app, pemKey)
	want := "the app is not installed on fnune/other. Install it, and give it access to the repository, at https://github.com/apps/fnune-agents/installations/new"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v", err)
	}
}

func TestATokenThatGitHubRefusesNamesThePermissions(t *testing.T) {
	key, pemKey := newKey(t)
	f := newFakeGitHub(t, key)
	f.tokenStatus = http.StatusUnprocessableEntity
	_, _, err := f.minter("https://github.com/fnune/doriath").Mint(context.Background(), app, pemKey)
	if err == nil || !strings.Contains(err.Error(), "GitHub refused the token for doriath") || !strings.Contains(err.Error(), "permissions requested are not granted") {
		t.Fatalf("err = %v", err)
	}
}

func TestRepositoriesInTheProfileReplaceTheRepositoryOfTheSession(t *testing.T) {
	key, pemKey := newKey(t)
	f := newFakeGitHub(t, key)
	f.installations["fnune/mirror"] = 7
	mirror := app
	mirror.Repositories = []string{"fnune/mirror", "fnune/doriath"}
	m := f.minter()
	m.Repository = ""
	v, _, err := m.Mint(context.Background(), mirror, pemKey)
	if err != nil || string(v.Reveal()) != "ghs_installation-7" {
		t.Fatalf("token %q, %v", v.Reveal(), err)
	}
	repos, _ := f.tokenReq["repositories"].([]any)
	if len(repos) != 2 || repos[0] != "mirror" || repos[1] != "doriath" {
		t.Errorf("repositories = %v", repos)
	}
}

func TestWithoutAGitHubRemoteTheErrorSaysWhatToAdd(t *testing.T) {
	key, pemKey := newKey(t)
	f := newFakeGitHub(t, key)
	_, _, err := f.minter("https://gitlab.com/fnune/doriath.git", "git@example.com:a/b").Mint(context.Background(), app, pemKey)
	if err == nil || !strings.Contains(err.Error(), "has no GitHub remote") || !strings.Contains(err.Error(), "repositories in github_app") {
		t.Errorf("err = %v", err)
	}
	m := f.minter()
	m.Repository = ""
	if _, _, err := m.Mint(context.Background(), app, pemKey); err == nil || !strings.Contains(err.Error(), "no repository") {
		t.Errorf("no repository: %v", err)
	}
	if len(f.paths()) != 0 {
		t.Errorf("GitHub was asked: %v", f.paths())
	}
}

func TestRemotesOfBothFormsNameTheOwnerAndTheRepository(t *testing.T) {
	for remote, want := range map[string]string{
		"https://github.com/fnune/doriath.git":          "fnune/doriath",
		"https://github.com/fnune/doriath":              "fnune/doriath",
		"https://github.com/fnune/doriath/":             "fnune/doriath",
		"https://x-access-token:tok@github.com/o/r.git": "o/r",
		"https://user@github.com/o/r.git":               "o/r",
		"https://GitHub.com/o/r.git":                    "",
		"git@github.com:fnune/doriath.git":              "fnune/doriath",
		"git@github.com:fnune/doriath":                  "fnune/doriath",
		"ssh://git@github.com/fnune/doriath.git":        "fnune/doriath",
		"ssh://git@github.com:22/fnune/doriath.git":     "fnune/doriath",
		"git@github.com:fnune/dori.ath.git":             "fnune/dori.ath",
		"https://github.com.evil.example/fnune/doriath": "",
		"https://example.com/github.com/fnune/doriath":  "",
		"git@gitlab.com:fnune/doriath.git":              "",
		"https://github.com/fnune":                      "",
		"https://github.com/fnune/doriath/pull/1":       "",
		"/home/fnune/src/doriath":                       "",
		"":                                              "",
	} {
		owner, repo, ok := ParseRemote(remote)
		got := ""
		if ok {
			got = owner + "/" + repo
		}
		if got != want {
			t.Errorf("ParseRemote(%q) = %q, want %q", remote, got, want)
		}
	}
}

func TestAPKCS8KeyWorksToo(t *testing.T) {
	key, _ := newKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil || !got.Equal(key) {
		t.Errorf("key = %v, %v", got, err)
	}
}
