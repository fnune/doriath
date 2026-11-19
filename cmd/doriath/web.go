package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/control"
	"github.com/fnune/doriath/internal/doctor"
	"github.com/fnune/doriath/internal/keyring"
	"github.com/fnune/doriath/internal/session"
	"github.com/fnune/doriath/internal/web"
)

const (
	defaultWebAddr  = "127.0.0.1:" + session.DefaultWebPort
	webTokenBytes   = 32
	webShutdownWait = 5 * time.Second
)

func cmdWeb(ctx context.Context, args []string, c clock, out io.Writer) error {
	p, err := paths()
	if err != nil {
		return err
	}
	if len(args) > 0 && args[0] == "open" {
		return cmdWebOpen(ctx, p, args[1:], out)
	}
	return serveWeb(ctx, p, args, c, out)
}

func serveWeb(ctx context.Context, p config.Paths, args []string, c clock, out io.Writer) error {
	flags := flag.NewFlagSet("web", flag.ContinueOnError)
	listen := flags.String("listen", defaultWebAddr, "the loopback HOST:PORT to serve on")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := web.Loopback(*listen); err != nil {
		return fmt.Errorf("web: %w", err)
	}
	user, err := config.LoadUser(p.UserConfig())
	if err != nil {
		return fmt.Errorf("web: %w", err)
	}
	token, err := pageToken(p)
	if err != nil {
		return fmt.Errorf("web: %w", err)
	}
	l, err := net.Listen("tcp", *listen)
	if errors.Is(err, syscall.EADDRINUSE) {
		fmt.Fprint(out, "The approvals page is already running.\n"+openHint(*listen))
		return nil
	}
	if err != nil {
		return fmt.Errorf("web: %w", err)
	}
	addr := l.Addr().String()
	if err := os.MkdirAll(filepath.Dir(p.WebAddr()), 0o700); err == nil {
		if err := os.WriteFile(p.WebAddr(), []byte(addr), 0o600); err == nil {
			defer os.Remove(p.WebAddr())
		}
	}
	checks := &doctorChecks{paths: p}
	go checks.Refresh(ctx)
	srv, err := web.New(liveApprovals{paths: p}, &auditHistory{path: p.AuditLog()}, checks, c, token, addr)
	if err != nil {
		_ = l.Close()
		return fmt.Errorf("web: %w", err)
	}
	fmt.Fprint(out, "The approvals page is running.\n"+openHint(addr)+"Press Ctrl+C to stop.\n")
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if user.Desktop.Tray {
		showTray(ctx, liveApprovals{paths: p}, p.Runtime, addr, token, symbolicTrayPath(p, os.Getenv("XDG_CURRENT_DESKTOP")), out)
	}
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), webShutdownWait)
		defer cancel()
		_ = hs.Shutdown(shutdown)
	}()
	if err := hs.Serve(l); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("web: %w", err)
	}
	return nil
}

func cmdWebOpen(ctx context.Context, p config.Paths, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("web open", flag.ContinueOnError)
	listen := flags.String("listen", servedAddr(p), "the HOST:PORT the page serves on")
	print := flags.Bool("print", false, "print a link that works once, in place of opening a browser")
	if err := flags.Parse(args); err != nil {
		return err
	}
	token, err := pageToken(p)
	if err != nil {
		return fmt.Errorf("web open: %w", err)
	}
	return openPage(ctx, p.Runtime, *listen, token, "", opener{}, *print || overSSH() || !hasDisplay(), out)
}

func servedAddr(p config.Paths) string {
	if data, err := os.ReadFile(p.WebAddr()); err == nil && web.Loopback(string(data)) == nil {
		return string(data)
	}
	return defaultWebAddr
}

type webPage struct{ paths config.Paths }

func (w webPage) Running() bool {
	token, err := pageToken(w.paths)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return servesPage(ctx, servedAddr(w.paths), token)
}

func (w webPage) Open(request, activation string) error {
	token, err := pageToken(w.paths)
	if err != nil {
		return err
	}
	return openPage(context.Background(), w.paths.Runtime, servedAddr(w.paths), token, request, opener{activation: activation}, false, io.Discard)
}

func hasDisplay() bool { return os.Getenv("WAYLAND_DISPLAY") != "" || os.Getenv("DISPLAY") != "" }

func overSSH() bool { return os.Getenv("SSH_CONNECTION") != "" }

func openHint(addr string) string {
	if !overSSH() {
		return "Open it with: `doriath web open`\n"
	}
	_, port, _ := net.SplitHostPort(addr)
	return fmt.Sprintf("You are on this machine over SSH. On your own machine, run:\n  ssh -L %s:127.0.0.1:%s %s\nThen run `doriath web open` here, and open its link in your own browser.\n", port, port, sshHost())
}

func sshHost() string {
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "HOST"
}

func codeLink(addr, code, request string) string {
	link := "http://" + addr + "/?code=" + code
	if request != "" {
		link += "&request=" + url.QueryEscape(request)
	}
	return link
}

func openPage(ctx context.Context, runtime, addr, token, request string, browser opener, print bool, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	notRunning := fmt.Errorf("web open: doriath is not serving on %s; start it with `doriath web`, or enable approvals.web in home-manager", addr)
	if !servesPage(ctx, addr, token) {
		return notRunning
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/code", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return notRunning
	}
	defer res.Body.Close()
	code, err := io.ReadAll(io.LimitReader(res.Body, 256))
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("web open: %s", strings.TrimSpace(string(code)))
	}
	if print {
		fmt.Fprintf(out, "%s\nThe link works once, for a minute.\n", codeLink(addr, string(code), request))
		return nil
	}
	file, err := writeSignInPage(runtime, addr, string(code), request, time.Now())
	if err != nil {
		return fmt.Errorf("web open: %w", err)
	}
	if err := browser.Open(file); err != nil {
		_ = os.Remove(file)
		return err
	}
	return nil
}

const signInPageLife = 2 * time.Minute

func writeSignInPage(dir, addr, code, request string, now time.Time) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	old, _ := filepath.Glob(filepath.Join(dir, "web-open-*.html"))
	for _, path := range old {
		if info, err := os.Stat(path); err == nil && now.Sub(info.ModTime()) > signInPageLife {
			_ = os.Remove(path)
		}
	}
	f, err := os.CreateTemp(dir, "web-open-*.html")
	if err != nil {
		return "", err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, signInPage, html.EscapeString("http://"+addr+"/redeem"), html.EscapeString(code), html.EscapeString(request))
	return f.Name(), err
}

const signInPage = `<!doctype html>
<meta charset="utf-8">
<title>Doriath</title>
<form id="f" method="post" action="%s">
<input type="hidden" name="code" value="%s">
<input type="hidden" name="request" value="%s">
<button>Open doriath</button>
</form>
<script>document.getElementById("f").submit()</script>
`

func servesPage(ctx context.Context, addr, token string) bool {
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return false
	}
	nonce := hex.EncodeToString(challenge)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/proof?challenge="+nonce, nil)
	if err != nil {
		return false
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	proof, err := io.ReadAll(io.LimitReader(res.Body, 256))
	return err == nil && res.StatusCode == http.StatusOK && subtle.ConstantTimeCompare(proof, []byte(web.Proof(token, nonce))) == 1
}

type doctorChecks struct {
	paths   config.Paths
	mu      sync.Mutex
	results []web.Check
	at      time.Time
}

func (d *doctorChecks) Checks() ([]web.Check, time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.results), d.at
}

func (d *doctorChecks) Refresh(ctx context.Context) {
	results := doctor.Run(ctx, doctor.Options{Paths: d.paths, Loader: loader(d.paths, ""), Keyring: keyring.Desktop{}, Logins: keyring.Logins{}})
	checks := make([]web.Check, len(results))
	for i, r := range results {
		checks[i] = web.Check{Name: r.Name, Level: string(r.Level), Detail: r.Detail}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.results, d.at = checks, time.Now()
}

func pageToken(p config.Paths) (string, error) {
	if err := os.Remove(p.LegacyWebToken()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("delete the page token of an earlier version: %w", err)
	}
	return webToken(p.WebToken())
}

func webToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return newWebToken(path)
	}
	if err != nil {
		return "", fmt.Errorf("read the page token: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("read the page token: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s has mode %o; others could read the page token. Run: `chmod 600 %s`", path, info.Mode().Perm(), path)
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 2*webTokenBytes {
		return "", fmt.Errorf("%s holds a token that is too short; delete the file and run `doriath web` again", path)
	}
	return token, nil
}

func newWebToken(path string) (string, error) {
	raw := make([]byte, webTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("create the runtime directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("write the page token: %w", err)
	}
	if _, err := f.WriteString(token + "\n"); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("write the page token: %w", err)
	}
	return token, f.Close()
}

type liveApprovals struct {
	paths config.Paths
}

func (l liveApprovals) Sessions(ctx context.Context) ([]web.Session, error) {
	sessions, err := liveSessions(l.paths)
	if err != nil {
		return nil, err
	}
	out := make([]web.Session, 0, len(sessions))
	for _, s := range sessions {
		var reqs []approval.Request
		if err := control.Call(ctx, s.control, session.MethodList, struct{}{}, &reqs); err != nil {
			continue
		}
		out = append(out, web.Session{ID: s.info.ID, Profile: s.info.Profile, Cwd: s.info.Cwd, Description: s.info.Description, Requests: reqs})
	}
	return out, nil
}

func (l liveApprovals) Decide(ctx context.Context, sessionID, id string, d approval.Decision) error {
	sessions, err := liveSessions(l.paths)
	if err != nil {
		return err
	}
	for _, s := range sessions {
		if s.info.ID == sessionID {
			return control.Call(ctx, s.control, session.MethodDecide, session.DecideParams{ID: id, Decision: d}, nil)
		}
	}
	return fmt.Errorf("session %s is no longer running", sessionID)
}

type auditHistory struct {
	path     string
	mu       sync.Mutex
	offset   int64
	answered []web.Answered
	ended    []web.Ended
}

func (h *auditHistory) Answered(_ context.Context, since time.Time) ([]web.Answered, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.read(since); err != nil {
		return nil, err
	}
	return slices.Clone(h.answered), nil
}

func (h *auditHistory) Ended(_ context.Context, since time.Time) ([]web.Ended, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.read(since); err != nil {
		return nil, err
	}
	return slices.Clone(h.ended), nil
}

func (h *auditHistory) read(since time.Time) error {
	f, err := os.Open(h.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() < h.offset {
		h.offset, h.answered, h.ended = 0, nil, nil
	}
	if _, err := f.Seek(h.offset, io.SeekStart); err != nil {
		return err
	}
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		h.offset += int64(len(line))
		var rec auditRecord
		if json.Unmarshal(line, &rec) != nil {
			continue
		}
		if a, ok := answeredRecord(rec); ok {
			h.answered = append(h.answered, a)
		}
		if e, ok := endedRecord(rec); ok {
			h.ended = append(h.ended, e)
		}
	}
	h.answered = slices.DeleteFunc(h.answered, func(a web.Answered) bool { return a.Time.Before(since) })
	h.ended = slices.DeleteFunc(h.ended, func(e web.Ended) bool { return e.Time.Before(since) })
	return nil
}

func answeredRecord(rec auditRecord) (web.Answered, bool) {
	if rec.Event != "approval-decided" {
		return web.Answered{}, false
	}
	var data struct {
		Request  approval.Request  `json:"request"`
		Decision approval.Decision `json:"decision"`
	}
	if json.Unmarshal(rec.Data, &data) != nil || data.Decision.By == approval.ByGrant {
		return web.Answered{}, false
	}
	return web.Answered{Time: rec.Time, Request: data.Request, Decision: data.Decision}, true
}

func endedRecord(rec auditRecord) (web.Ended, bool) {
	if rec.Event != "session-end" {
		return web.Ended{}, false
	}
	var data struct {
		Exit   int `json:"exit"`
		Denied []struct {
			Host   string `json:"host"`
			Reason string `json:"reason"`
			Count  int    `json:"count"`
		} `json:"denied"`
	}
	if json.Unmarshal(rec.Data, &data) != nil {
		return web.Ended{}, false
	}
	e := web.Ended{Time: rec.Time, Session: rec.Session, Profile: rec.Profile, Exit: data.Exit}
	for _, d := range data.Denied {
		e.Blocked = append(e.Blocked, web.Blocked{Target: d.Host, Reason: d.Reason, Count: d.Count})
	}
	return e, true
}
