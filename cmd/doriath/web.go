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
	"io"
	"net"
	"net/http"
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
	"github.com/fnune/doriath/internal/session"
	"github.com/fnune/doriath/internal/web"
)

const (
	defaultWebAddr  = "127.0.0.1:7341"
	webTokenBytes   = 32
	webShutdownWait = 5 * time.Second
)

func cmdApprovalsWeb(ctx context.Context, p config.Paths, args []string, c clock, out io.Writer) error {
	flags := flag.NewFlagSet("approvals web", flag.ContinueOnError)
	listen := flags.String("listen", defaultWebAddr, "the loopback HOST:PORT to serve on")
	open := flags.Bool("open", false, "open the page in your browser")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := web.Loopback(*listen); err != nil {
		return fmt.Errorf("approvals web: %w", err)
	}
	token, err := webToken(p.WebToken())
	if err != nil {
		return fmt.Errorf("approvals web: %w", err)
	}
	l, err := net.Listen("tcp", *listen)
	if errors.Is(err, syscall.EADDRINUSE) {
		return showProvenPage(ctx, *listen, token, *open, out)
	}
	if err != nil {
		return fmt.Errorf("approvals web: %w", err)
	}
	addr := l.Addr().String()
	srv, err := web.New(liveApprovals{paths: p}, &auditHistory{path: p.AuditLog()}, c, token, addr)
	if err != nil {
		_ = l.Close()
		return fmt.Errorf("approvals web: %w", err)
	}
	link := pageLink(addr, token)
	fmt.Fprintf(out, "Doriath is at %s\nPress Ctrl+C to stop.\n", link)
	if *open {
		if err := (opener{}).Open(link); err != nil {
			fmt.Fprintln(out, "Could not open a browser:", err)
		}
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), webShutdownWait)
		defer cancel()
		_ = hs.Shutdown(shutdown)
	}()
	if err := hs.Serve(l); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("approvals web: %w", err)
	}
	return nil
}

func pageLink(addr, token string) string { return "http://" + addr + "/?token=" + token }

func showProvenPage(ctx context.Context, addr, token string, open bool, out io.Writer) error {
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	nonce := hex.EncodeToString(challenge)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/proof?challenge="+nonce, nil)
	if err != nil {
		return err
	}
	inUse := fmt.Errorf("approvals web: another program uses %s; choose another address with --listen", addr)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return inUse
	}
	defer res.Body.Close()
	proof, err := io.ReadAll(io.LimitReader(res.Body, 256))
	if err != nil || res.StatusCode != http.StatusOK || subtle.ConstantTimeCompare(proof, []byte(web.Proof(token, nonce))) != 1 {
		return inUse
	}
	link := pageLink(addr, token)
	fmt.Fprintf(out, "Doriath is already running at %s\n", link)
	if open {
		return (opener{}).Open(link)
	}
	return nil
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
		return "", fmt.Errorf("%s has mode %o; others could read the page token. Run: chmod 600 %s", path, info.Mode().Perm(), path)
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 2*webTokenBytes {
		return "", fmt.Errorf("%s holds a token that is too short; delete the file and run doriath approvals web again", path)
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
		return "", fmt.Errorf("create the state directory: %w", err)
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
		out = append(out, web.Session{ID: s.info.ID, Profile: s.info.Profile, Cwd: s.info.Cwd, Requests: reqs})
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
}

func (h *auditHistory) Answered(_ context.Context, since time.Time) ([]web.Answered, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	f, err := os.Open(h.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() < h.offset {
		h.offset, h.answered = 0, nil
	}
	if _, err := f.Seek(h.offset, io.SeekStart); err != nil {
		return nil, err
	}
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		h.offset += int64(len(line))
		if a, ok := answeredRecord(line); ok {
			h.answered = append(h.answered, a)
		}
	}
	h.answered = slices.DeleteFunc(h.answered, func(a web.Answered) bool { return a.Time.Before(since) })
	return slices.Clone(h.answered), nil
}

func answeredRecord(line []byte) (web.Answered, bool) {
	var rec auditRecord
	if json.Unmarshal(line, &rec) != nil || rec.Event != "approval-decided" {
		return web.Answered{}, false
	}
	var data struct {
		Request  approval.Request  `json:"request"`
		Decision approval.Decision `json:"decision"`
	}
	if json.Unmarshal(rec.Data, &data) != nil {
		return web.Answered{}, false
	}
	return web.Answered{Time: rec.Time, Request: data.Request, Decision: data.Decision}, true
}
