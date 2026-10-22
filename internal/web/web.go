// Package web serves the approvals page on a loopback address. A browser
// reaches it only with the token from the link the command prints, so other
// local users and other web pages cannot read or answer requests.
package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
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

type History interface {
	Answered(ctx context.Context, since time.Time) ([]Answered, error)
}

type Clock interface {
	Now() time.Time
}

const (
	cookieName    = "doriath_token"
	cookieMaxAge  = 30 * 24 * time.Hour
	maxFormBody   = 4 << 10
	minTokenBytes = 32
)

//go:embed assets
var assets embed.FS

var pages = template.Must(template.ParseFS(assets, "assets/*.html"))

type Server struct {
	sessions Sessions
	history  History
	clock    Clock
	token    string
}

// New serves the page for addr, the host:port it listens on.
func New(sessions Sessions, history History, clock Clock, token, addr string) (*Server, error) {
	if err := Loopback(addr); err != nil {
		return nil, err
	}
	if len(token) < minTokenBytes {
		return nil, errors.New("the page token is too short")
	}
	return &Server{
		sessions: sessions,
		history:  history,
		clock:    clock,
		token:    token,
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
			http.Error(w, "doriath: open the link doriath approvals web printed", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if t := r.URL.Query().Get("token"); t != "" {
		if !s.validToken(t) {
			http.Error(w, "doriath: this link is not valid; open the one doriath approvals web printed", http.StatusUnauthorized)
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
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !s.signedIn(r) {
		http.Error(w, "doriath: open the link doriath approvals web printed", http.StatusUnauthorized)
		return
	}
	s.render(w, r, "page", http.StatusOK, r.URL.Query().Get("request"), "")
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
	s.render(w, r, "main", http.StatusOK, r.URL.Query().Get("request"), "")
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
		s.render(w, r, "main", http.StatusOK, selected, problem)
		return
	}
	s.render(w, r, "page", status, selected, problem)
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

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, status int, selected, problem string) {
	view, err := s.view(r.Context(), selected)
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
