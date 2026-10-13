// Package session runs one agent inside a jail, with the proxy, broker,
// approvals and signing agent that serve it.
package session

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fnune/girdle/internal/agents/claude"
	"github.com/fnune/girdle/internal/approval"
	"github.com/fnune/girdle/internal/audit"
	"github.com/fnune/girdle/internal/ca"
	"github.com/fnune/girdle/internal/config"
	"github.com/fnune/girdle/internal/jail"
	"github.com/fnune/girdle/internal/jailinit"
	"github.com/fnune/girdle/internal/profile"
	"github.com/fnune/girdle/internal/proxy"
	"github.com/fnune/girdle/internal/secret"
	"github.com/fnune/girdle/internal/sshagent"
)

// Socket and file names in the jail directory.
const (
	ProxySocket   = "proxy.sock"
	BrokerSocket  = "broker.sock"
	AgentSocket   = "ssh-agent.sock"
	PodmanSocket  = "podman.sock"
	ControlSocket = "control.sock"
	InfoFile      = "session.json"
)

const placeholderToken = "girdle-placeholder-token"

// Informer shows a message that needs no decision.
type Informer interface {
	Inform(title, body string) error
}

type Deps struct {
	Paths    config.Paths
	User     config.User
	Secrets  secret.Store
	Notifier approval.Notifier
	Informer Informer
	Clock    approval.Clock
	Dialer   proxy.Dialer
	Getenv   func(string) string
	Environ  []string
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer
	// Bwrap is the bubblewrap binary.
	Bwrap string
	// Exe is girdle's own binary, which runs as init inside the jail.
	Exe string
	// GitDesktop is the desktop's global git config as git config --list -z
	// prints it.
	GitDesktop []byte
	// Unshare and Nsenter are util-linux tools for the podman service and
	// for joining its network namespace. Podman is the podman binary.
	Unshare string
	Nsenter string
	Podman  string
	// UpstreamRoots verifies upstream servers in tests. Nil means the system
	// roots.
	UpstreamRoots *x509.CertPool
}

type Request struct {
	Profile *profile.Profile
	Cwd     string
	Command []string
}

// Info describes a running session for girdle approvals and girdle status.
type Info struct {
	ID      string    `json:"id"`
	Profile string    `json:"profile"`
	Cwd     string    `json:"cwd"`
	Command []string  `json:"command"`
	PID     int       `json:"pid"`
	Started time.Time `json:"started"`
}

type Session struct {
	deps    Deps
	req     Request
	id      string
	dir     string
	jailDir string
	log     *audit.Log
	logFile io.Closer
	manager *approval.Manager
	closers []func()
	// netnsPID is a process in the podman service's namespaces. When set,
	// the agent joins its user and network namespaces.
	netnsPID int
	// nsenter joins netns. Empty when the agent gets its own namespace.
	nsenter string
}

func New(deps Deps, req Request) (*Session, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(deps.Paths.Sessions(), id)
	return &Session{deps: deps, req: req, id: id, dir: dir, jailDir: filepath.Join(dir, "jail")}, nil
}

func (s *Session) ID() string { return s.id }

// Run prepares the jail, runs the command in it and returns its exit code.
func (s *Session) Run(ctx context.Context) (int, error) {
	defer s.cleanup()
	if err := s.prepare(ctx); err != nil {
		return 1, err
	}
	spec, err := s.plan()
	if err != nil {
		return 1, err
	}
	return s.exec(ctx, spec)
}

func (s *Session) prepare(ctx context.Context) error {
	p := s.req.Profile
	if err := os.MkdirAll(s.jailDir, 0o700); err != nil {
		return fmt.Errorf("create session directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(s.dir), 0o700); err != nil {
		return fmt.Errorf("protect sessions directory: %w", err)
	}
	s.closers = append(s.closers, func() { _ = os.RemoveAll(s.dir) })

	f, err := audit.OpenFile(s.deps.Paths.AuditLog())
	if err != nil {
		return err
	}
	s.logFile = f
	s.log = audit.New(f, s.deps.Clock.Now, s.id, p.Name)
	s.log.Write("session-start", map[string]any{"cwd": s.req.Cwd, "command": s.req.Command})
	s.manager = approval.NewManager(s.deps.Clock, s.deps.Notifier, s.log, randomIDs{})

	for _, d := range []string{s.cacheRoot(), s.tmp()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", d, err)
		}
	}
	for _, c := range p.Caches {
		if err := os.MkdirAll(jail.CacheSource(s.cacheRoot(), c.Path, s.deps.Paths.Home), 0o700); err != nil {
			return fmt.Errorf("create cache for %s: %w", c.Path, err)
		}
	}

	if err := s.startProxy(ctx); err != nil {
		return err
	}
	for _, port := range p.Egress.Ports {
		if err := s.startForward(ctx, port); err != nil {
			return err
		}
	}
	if err := s.startBroker(ctx); err != nil {
		return err
	}
	if err := s.startControl(ctx); err != nil {
		return err
	}
	if err := s.startSigning(ctx); err != nil {
		return err
	}
	if p.Podman {
		if err := s.startPodman(ctx); err != nil {
			return err
		}
	}
	if err := s.writeGitFiles(); err != nil {
		return err
	}
	if claude.Matches(s.req.Command) {
		if err := s.prepareClaude(); err != nil {
			return err
		}
	}
	return s.writeInfo()
}

func (s *Session) cacheRoot() string { return s.deps.Paths.AgentCache(s.req.Profile.Name) }
func (s *Session) tmp() string       { return filepath.Join(s.cacheRoot(), "tmp") }
func (s *Session) jailPath(name string) string {
	return filepath.Join(s.jailDir, name)
}

func (s *Session) listen(name string) (net.Listener, error) {
	path := s.jailPath(name)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("protect %s: %w", path, err)
	}
	s.closers = append(s.closers, func() { _ = l.Close() })
	return l, nil
}

func (s *Session) startProxy(ctx context.Context) error {
	p := s.req.Profile
	var hosts []string
	for _, h := range p.HTTP {
		hosts = append(hosts, string(h.Host))
	}
	var issuer proxy.Issuer = noIssuer{}
	var caPEM []byte
	if len(hosts) > 0 {
		authority, err := ca.New(hosts, s.deps.Clock.Now)
		if err != nil {
			return err
		}
		issuer = authority
		caPEM = authority.CertPEM()
	}
	if err := writeFile(s.jailPath("ca.pem"), caPEM, 0o644); err != nil {
		return err
	}
	bundle, err := CABundle(s.deps.Getenv, os.ReadFile, caPEM)
	if err != nil {
		return err
	}
	if err := writeFile(s.jailPath("ca-bundle.pem"), bundle, 0o644); err != nil {
		return err
	}
	srv := proxy.New(proxy.Config{
		Session:       s.id,
		Profile:       p.Name,
		ApprovalTTL:   approvalTTL,
		UpstreamRoots: s.deps.UpstreamRoots,
	}, p, s.manager, s.deps.Secrets, issuer, s.deps.Dialer, s.log)
	l, err := s.listen(ProxySocket)
	if err != nil {
		return err
	}
	go func() { _ = srv.Serve(l) }()
	return nil
}

const approvalTTL = 10 * time.Minute

func (s *Session) startForward(ctx context.Context, port int) error {
	l, err := s.listen(fmt.Sprintf("port-%d.sock", port))
	if err != nil {
		return err
	}
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				up, err := s.deps.Dialer.DialContext(ctx, "tcp", target)
				if err != nil {
					s.log.Egress(proxy.Event{Kind: "error", Host: "127.0.0.1", Port: strconv.Itoa(port), Reason: err.Error()})
					return
				}
				defer up.Close()
				splice(conn, up)
			}()
		}
	}()
	return nil
}

func (s *Session) startSigning(context.Context) error {
	p := s.req.Profile
	if p.SigningKey == "" {
		return nil
	}
	key, err := s.deps.Secrets.Get(context.Background(), p.SecretName(p.SigningKey))
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	a, err := sshagent.New(key.Reveal(), "girdle "+p.Name, []string{"git"})
	if err != nil {
		return err
	}
	if err := writeFile(s.jailPath("signing.pub"), a.AuthorizedKey(), 0o644); err != nil {
		return err
	}
	l, err := s.listen(AgentSocket)
	if err != nil {
		return err
	}
	go func() { _ = a.Serve(l) }()
	return nil
}

func (s *Session) writeGitFiles() error {
	p := s.req.Profile
	signing := ""
	if p.SigningKey != "" {
		signing = jail.InJail("signing.pub")
	}
	var rewrite []string
	for _, h := range p.HTTP {
		if !strings.HasPrefix(string(h.Host), "*.") && h.Credential != nil && h.Credential.Scheme == profile.SchemeBasic {
			rewrite = append(rewrite, string(h.Host))
		}
	}
	if err := writeFile(s.jailPath("gitconfig"), GitConfig(GitOptions{SigningKey: signing, RewriteSSH: rewrite, Desktop: s.deps.GitDesktop}), 0o644); err != nil {
		return err
	}
	return writeFile(s.jailPath("jj.toml"), JJConfig(signing), 0o644)
}

func (s *Session) prepareClaude() error {
	home := s.deps.Paths.Home
	private := filepath.Join(s.cacheRoot(), "claude")
	for _, name := range append(claude.Masked(), "projects") {
		path := filepath.Join(private, name)
		if claude.MaskIsFile(name) {
			if err := os.MkdirAll(private, 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
			if err != nil {
				return fmt.Errorf("create %s: %w", path, err)
			}
			_ = f.Close()
			continue
		}
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", path, err)
		}
	}
	own := filepath.Join(home, ".claude", "projects", claude.ProjectDir(s.req.Cwd))
	if err := os.MkdirAll(own, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", own, err)
	}
	if err := os.MkdirAll(filepath.Join(private, "projects", claude.ProjectDir(s.req.Cwd)), 0o700); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(home, ".claude.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read ~/.claude.json: %w", err)
	}
	if len(data) == 0 {
		data = []byte("{}\n")
	}
	if err := writeFile(filepath.Join(private, "claude.json"), data, 0o600); err != nil {
		return err
	}
	settings, err := claude.Settings(s.req.Profile, s.req.Cwd, osFiles{})
	if err != nil {
		return err
	}
	return writeFile(s.jailPath("claude-settings.json"), settings, 0o644)
}

func (s *Session) writeInfo() error {
	info := Info{ID: s.id, Profile: s.req.Profile.Name, Cwd: s.req.Cwd, Command: s.req.Command, PID: os.Getpid(), Started: s.deps.Clock.Now()}
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(s.dir, InfoFile), data, 0o600)
}

func (s *Session) layout() jail.Layout {
	return jail.Layout{JailDir: s.jailDir, CacheRoot: s.cacheRoot(), Tmp: s.tmp(), Exe: s.deps.Exe}
}

func (s *Session) forwards() []string {
	out := []string{fmt.Sprintf("%d=%s", jail.ProxyPort, jail.InJail(ProxySocket))}
	for _, port := range s.req.Profile.Egress.Ports {
		out = append(out, fmt.Sprintf("%d=%s", port, jail.InJail(fmt.Sprintf("port-%d.sock", port))))
	}
	return out
}

func (s *Session) plan() (jail.Spec, error) {
	p := s.req.Profile
	home := s.deps.Paths.Home
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", jail.ProxyPort)
	env := map[string]string{
		"HTTP_PROXY":          proxyURL,
		"HTTPS_PROXY":         proxyURL,
		"http_proxy":          proxyURL,
		"https_proxy":         proxyURL,
		"NO_PROXY":            "localhost,127.0.0.1,::1",
		"no_proxy":            "localhost,127.0.0.1,::1",
		"SSL_CERT_FILE":       jail.InJail("ca-bundle.pem"),
		"NIX_SSL_CERT_FILE":   jail.InJail("ca-bundle.pem"),
		"CURL_CA_BUNDLE":      jail.InJail("ca-bundle.pem"),
		"GIT_SSL_CAINFO":      jail.InJail("ca-bundle.pem"),
		"REQUESTS_CA_BUNDLE":  jail.InJail("ca-bundle.pem"),
		"NODE_EXTRA_CA_CERTS": jail.InJail("ca.pem"),
		"GIT_CONFIG_GLOBAL":   jail.InJail("gitconfig"),
		"JJ_CONFIG":           JJConfigPath(home, osHost{}.Kind, jail.InJail("jj.toml")),
		"GIRDLE_SESSION":      s.id,
		"GIRDLE_BROKER":       jail.InJail(BrokerSocket),
	}
	if p.SigningKey != "" {
		env["SSH_AUTH_SOCK"] = jail.InJail(AgentSocket)
	}
	if _, ok := p.Intercepted("api.github.com"); ok {
		env["GH_TOKEN"] = placeholderToken
	}
	if p.Podman {
		env["CONTAINER_HOST"] = "unix://" + jail.InJail(PodmanSocket)
		env["DOCKER_HOST"] = "unix://" + jail.InJail(PodmanSocket)
	}

	// In a shared namespace the podman service's init already holds the
	// forwards.
	var forwards []string
	if s.netnsPID == 0 {
		forwards = s.forwards()
	}
	command := s.req.Command
	var extra []jail.Bind
	if claude.Matches(command) {
		command = claude.Args(command, jail.InJail("claude-settings.json"))
		st := claude.State{Home: home, Cwd: s.req.Cwd, Private: filepath.Join(s.cacheRoot(), "claude"), ConfigCopy: filepath.Join(s.cacheRoot(), "claude", "claude.json")}
		extra = append(extra, st.Binds(osHost{})...)
	}
	argv := []string{jail.ExePath, "init"}
	for _, f := range forwards {
		argv = append(argv, "--forward", f)
	}
	argv = append(argv, "--")
	argv = append(argv, command...)

	return jail.Plan(p, s.layout(), jail.Options{
		SkipNetNS:  s.netnsPID != 0,
		SetIDs:     s.netnsPID != 0,
		GID:        os.Getgid(),
		UID:        os.Getuid(),
		Home:       home,
		Cwd:        s.req.Cwd,
		Command:    argv,
		HostEnv:    envMap(s.deps.Environ),
		ExtraEnv:   env,
		ExtraBinds: extra,
	}, osHost{})
}

func (s *Session) exec(ctx context.Context, spec jail.Spec) (int, error) {
	cmd := exec.Command(s.deps.Bwrap, spec.Args()...)
	if s.netnsPID != 0 {
		if s.deps.Nsenter == "" {
			return 1, errors.New("joining the podman network namespace needs util-linux nsenter")
		}
		// Joining a network namespace needs CAP_SYS_ADMIN in the namespace's
		// owner, which the agent only has after joining that user namespace.
		target := strconv.Itoa(s.netnsPID)
		cmd = exec.Command(s.deps.Nsenter, append([]string{"--target", target, "--user", "--net", "--", s.deps.Bwrap}, spec.Args()...)...)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = s.deps.Stdin, s.deps.Stdout, s.deps.Stderr
	cmd.Env = []string{}
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTSTP)
	defer signal.Reset(syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTSTP)
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("start bubblewrap: %w", err)
	}
	done := make(chan struct{})
	go func() {
		select {
		case sig := <-sigs:
			_ = cmd.Process.Signal(sig)
		case <-ctx.Done():
			_ = cmd.Process.Signal(syscall.SIGTERM)
		case <-done:
		}
	}()
	err := cmd.Wait()
	close(done)
	code := 0
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		code = exit.ExitCode()
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			code = 128 + int(ws.Signal())
		}
	case err != nil:
		return 1, fmt.Errorf("bubblewrap: %w", err)
	}
	s.log.Write("session-end", map[string]int{"exit": code})
	return code, nil
}

func (s *Session) cleanup() {
	for i := len(s.closers) - 1; i >= 0; i-- {
		s.closers[i]()
	}
	if s.logFile != nil {
		_ = s.logFile.Close()
	}
}

func envMap(environ []string) map[string]string {
	m := map[string]string{}
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	return m
}

func newID() (string, error) {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session id: %w", err)
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}

type randomIDs struct{}

func (randomIDs) New() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

type noIssuer struct{}

func (noIssuer) Certificate(host string) (*tlsCertificate, error) {
	return nil, fmt.Errorf("no intercepted hosts in this session: %s", host)
}

type osFiles struct{}

func (osFiles) ReadFile(p string) ([]byte, error) { return os.ReadFile(p) }

type osHost struct{}

func (osHost) Kind(p string) string {
	info, err := os.Lstat(p)
	if err != nil {
		return ""
	}
	switch {
	case info.IsDir():
		return "dir"
	case info.Mode().IsRegular():
		return "file"
	case info.Mode()&os.ModeSymlink != 0:
		if target, err := os.Stat(p); err == nil && target.IsDir() {
			return "dir"
		}
		return "other"
	}
	return "other"
}

func splice(a, b net.Conn) { jailinit.Splice(a, b) }
