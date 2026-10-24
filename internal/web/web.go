// Package web serves doriath's page on a loopback address. A browser
// reaches it only with the token from the link the command prints, or with a
// one-time code that doriath web open gets with the token, so other local
// users and other web pages cannot read or answer requests.
package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/ui"
)

type Session struct {
	ID       string
	Profile  string
	Cwd      string
	Requests []approval.Request
}

type Answered struct {
	Time     time.Time
	Request  approval.Request
	Decision approval.Decision
}

type Sessions interface {
	Sessions(ctx context.Context) ([]Session, error)
	Decide(ctx context.Context, session, id string, d approval.Decision) error
}

type Ended struct {
	Time    time.Time
	Session string
	Profile string
	Exit    int
	Blocked []Blocked
}

type Blocked struct {
	Host   string
	Reason string
	Count  int
}

type History interface {
	Answered(ctx context.Context, since time.Time) ([]Answered, error)
	Ended(ctx context.Context, since time.Time) ([]Ended, error)
}

type Check struct {
	Name   string
	Level  string
	Detail string
}

// Checks keeps the results of doriath doctor, which start programs and
// reach the session bus, so the page does not run them on every refresh.
type Checks interface {
	Checks() (results []Check, at time.Time)
	Refresh(ctx context.Context)
}

type Clock interface {
	Now() time.Time
}

const (
	cookieName    = "doriath_token"
	cookieMaxAge  = 30 * 24 * time.Hour
	maxFormBody   = 4 << 10
	minTokenBytes = 32
	codeBytes     = 16
	codeLifetime  = time.Minute
	maxCodes      = 16
)

//go:embed assets
var assets embed.FS

var pages = template.Must(template.ParseFS(assets, "assets/*.html"))

type Server struct {
	sessions Sessions
	history  History
	checks   Checks
	clock    Clock
	token    string

	mu    sync.Mutex
	codes map[string]time.Time
}

// New serves the page for addr, the host:port it listens on.
func New(sessions Sessions, history History, checks Checks, clock Clock, token, addr string) (*Server, error) {
	if err := Loopback(addr); err != nil {
		return nil, err
	}
	if len(token) < minTokenBytes {
		return nil, errors.New("the page token is too short")
	}
	return &Server{
		sessions: sessions,
		history:  history,
		checks:   checks,
		clock:    clock,
		token:    token,
		codes:    map[string]time.Time{},
	}, nil
}

// Loopback refuses an address other machines could reach.
func Loopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen address %q: %w", addr, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address %q: the page serves only on a loopback address such as 127.0.0.1", addr)
	}
	return nil
}

// Proof answers a challenge with the token, so that a command can check
// that the program on the port is this page before it opens the link.
func Proof(token, challenge string) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("doriath-web-proof\x00" + challenge))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) Handler() http.Handler {
	static, err := fs.Sub(assets, "assets")
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServerFS(static)))
	mux.Handle("GET /ui/", http.StripPrefix("/ui/", http.FileServerFS(ui.Assets)))
	mux.HandleFunc("GET /proof", s.proof)
	mux.HandleFunc("POST /code", s.code)
	mux.HandleFunc("POST /checks", s.authorized(s.recheck))
	mux.HandleFunc("GET /main", s.authorized(s.main))
	mux.HandleFunc("POST /decide", s.authorized(s.decide))
	return s.guard(mux)
}

func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if !loopbackName(r.Host) {
			http.Error(w, "doriath: this page answers only on the address it printed", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loopbackName(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) validToken(t string) bool {
	return subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) == 1
}

func (s *Server) signedIn(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	return err == nil && s.validToken(c.Value)
}

func (s *Server) authorized(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.signedIn(r) {
			http.Error(w, notSignedIn, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

const notSignedIn = "doriath: run doriath web open to open this page"

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if t, c := q.Get("token"), q.Get("code"); t != "" || c != "" {
		if !s.validToken(t) && !s.useCode(c) {
			http.Error(w, "doriath: this link is not valid or has expired; run doriath web open for a new one", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    s.token,
			Path:     "/",
			MaxAge:   int(cookieMaxAge.Seconds()),
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		target := "/"
		if req := q.Get("request"); req != "" {
			target += "?request=" + url.QueryEscape(req)
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}
	if !s.signedIn(r) {
		http.Error(w, notSignedIn, http.StatusUnauthorized)
		return
	}
	s.render(w, r, "page", http.StatusOK, r.URL.Query().Get("request"), "", true)
}

func (s *Server) code(w http.ResponseWriter, r *http.Request) {
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !s.validToken(bearer) {
		http.Error(w, "doriath: send the page token", http.StatusUnauthorized)
		return
	}
	c, err := s.NewCode()
	if errors.Is(err, errTooManyCodes) {
		http.Error(w, "doriath: "+err.Error(), http.StatusTooManyRequests)
		return
	}
	if err != nil {
		http.Error(w, "doriath: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(c))
}

var errTooManyCodes = errors.New("too many open links; wait a minute")

// NewCode returns a code for a link that signs a browser in once, within a
// minute.
func (s *Server) NewCode() (string, error) {
	raw := make([]byte, codeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	c := hex.EncodeToString(raw)
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	maps.DeleteFunc(s.codes, func(_ string, expires time.Time) bool { return !now.Before(expires) })
	if len(s.codes) >= maxCodes {
		return "", errTooManyCodes
	}
	s.codes[c] = now.Add(codeLifetime)
	return c, nil
}

func (s *Server) useCode(c string) bool {
	if c == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	expires, ok := s.codes[c]
	delete(s.codes, c)
	return ok && s.clock.Now().Before(expires)
}

func (s *Server) recheck(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "doriath: checks run only from this page", http.StatusForbidden)
		return
	}
	s.checks.Refresh(r.Context())
	s.renderAfter(w, r, http.StatusOK, "", "")
}

func (s *Server) proof(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("challenge")
	if len(challenge) < 16 || len(challenge) > 128 {
		http.Error(w, "doriath: send a challenge of 16 to 128 characters", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(Proof(s.token, challenge)))
}

func (s *Server) main(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "main", http.StatusOK, r.URL.Query().Get("request"), "", false)
}

func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "doriath: answers come only from this page", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "doriath: read the answer: "+err.Error(), http.StatusBadRequest)
		return
	}
	session, id, answer := r.PostForm.Get("session"), r.PostForm.Get("id"), r.PostForm.Get("answer")
	if err := s.answer(r.Context(), session, id, answer); err != nil {
		s.renderAfter(w, r, http.StatusConflict, session+"/"+id, err.Error())
		return
	}
	if sentByHtmx(r) {
		s.renderAfter(w, r, http.StatusOK, "", "")
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func sentByHtmx(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }

func (s *Server) renderAfter(w http.ResponseWriter, r *http.Request, status int, selected, problem string) {
	if sentByHtmx(r) {
		s.render(w, r, "main", http.StatusOK, selected, problem, false)
		return
	}
	s.render(w, r, "page", status, selected, problem, false)
}

func (s *Server) answer(ctx context.Context, session, id, answer string) error {
	req, err := s.find(ctx, session, id)
	if err != nil {
		return err
	}
	d, err := decision(req.Kind, answer)
	if err != nil {
		return err
	}
	return s.sessions.Decide(ctx, session, id, d)
}

func (s *Server) sameOrigin(r *http.Request) bool {
	return r.Header.Get("Origin") == "http://"+r.Host
}

func (s *Server) find(ctx context.Context, session, id string) (approval.Request, error) {
	sessions, err := s.sessions.Sessions(ctx)
	if err != nil {
		return approval.Request{}, err
	}
	for _, sess := range sessions {
		if sess.ID != session {
			continue
		}
		for _, req := range sess.Requests {
			if req.ID == id {
				return req, nil
			}
		}
	}
	return approval.Request{}, fmt.Errorf("request %s is no longer waiting", id)
}

func decision(kind approval.Kind, answer string) (approval.Decision, error) {
	switch answer {
	case "once":
		if !kind.AllowsOnce() {
			return approval.Decision{}, fmt.Errorf("a %s request is allowed for the session or not at all", kind)
		}
		return approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingOnce, By: "web"}, nil
	case "session":
		return approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession, By: "web"}, nil
	case "deny":
		return approval.Decision{Verdict: approval.VerdictDeny, By: "web"}, nil
	}
	return approval.Decision{}, fmt.Errorf("answer %q: want once, session or deny", answer)
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, status int, selected, problem string, orOldest bool) {
	view, err := s.view(r.Context(), selected, orOldest)
	if err != nil {
		view.Problem = err.Error()
	}
	if problem != "" {
		view.Problem = problem
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = pages.ExecuteTemplate(w, name, view)
}
