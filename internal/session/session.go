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
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	"github.com/fnune/girdle/internal/seccomp"
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
	Git     string
	// UpstreamRoots verifies upstream servers in tests. Nil means the system
	// roots.
	UpstreamRoots *x509.CertPool
}

type Request struct {
	Profile *profile.Profile
	Cwd     string
	Command []string
	// CloneFrom reuses the clones of an earlier session, so that resumed
	// work keeps its uncommitted changes.
	CloneFrom string
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
	egress  *egressLog
	policy  *livePolicy
	peers   *hostPeers
	clones  []repoClone
	logFile io.Closer
	manager *approval.Manager
	closers []func()
	// netnsPID is a process in the podman service's namespaces. When set,
	// the agent joins its user and network namespaces.
	netnsPID int
}

func New(deps Deps, req Request) (*Session, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(deps.Paths.Sessions(), id)
	return &Session{deps: deps, req: req, id: id, dir: dir, jailDir: filepath.Join(dir, "jail"), peers: &hostPeers{}}, nil
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
	s.egress = newEgressLog(s.log)
	s.policy = newLivePolicy(p)
	s.manager = approval.NewManager(s.deps.Clock, s.deps.Notifier, s.log, randomIDs{})
	s.egress.firstDenial = s.proposeHost

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

	if err := s.prepareClones(ctx); err != nil {
		return err
	}
	if err := s.startProxy(); err != nil {
		return err
	}
	for _, f := range p.Egress.Forwards() {
		if err := s.startForward(ctx, f); err != nil {
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
		if err := s.startPodman(); err != nil {
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

func (s *Session) startProxy() error {
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
	}, s.policy, s.manager, s.deps.Secrets, issuer, s.deps.Dialer, s.egress)
	l, err := s.listen(ProxySocket)
	if err != nil {
		return err
	}
	go func() { _ = srv.Serve(&proxy.IdentifyingListener{Listener: l, Peers: s.peers}) }()
	return nil
}

const approvalTTL = 10 * time.Minute

func (s *Session) startForward(ctx context.Context, f profile.Forward) error {
	l, err := s.listen(fmt.Sprintf("port-%d.sock", f.Port))
	if err != nil {
		return err
	}
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(f.Port))
	if !f.TCP {
		srv := &http.Server{Handler: s.httpForward(target, f.Port), ReadHeaderTimeout: 30 * time.Second}
		go func() { _ = srv.Serve(l) }()
		return nil
	}
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
					s.egress.Egress(proxy.Event{Kind: "error", Host: "127.0.0.1", Port: strconv.Itoa(f.Port), Reason: err.Error()})
					return
				}
				defer up.Close()
				splice(conn, up)
			}()
		}
	}()
	return nil
}

// httpForward reaches a host dev server as HTTP only. Anything that is not
// HTTP fails to parse, and websocket upgrades still work for hot reload.
func (s *Session) httpForward(target string, port int) http.Handler {
	transport := &http.Transport{DialContext: s.deps.Dialer.DialContext, MaxIdleConnsPerHost: 8, IdleConnTimeout: 90 * time.Second}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = target
		},
		Transport:     transport,
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.egress.Egress(proxy.Event{Kind: "error", Host: "127.0.0.1", Port: strconv.Itoa(port), Method: r.Method, Path: r.URL.Path, Reason: err.Error()})
			http.Error(w, fmt.Sprintf("girdle: nothing answers on port %d: %v", port, err), http.StatusBadGateway)
		},
	}
	var seen sync.Once
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Do(func() { s.egress.Egress(proxy.Event{Kind: "port", Host: "127.0.0.1", Port: strconv.Itoa(port)}) })
		rp.ServeHTTP(w, r)
	})
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
	own := filepath.Join(home, ".claude", "projects", claude.ProjectDir(s.req.Cwd))
	for _, d := range []string{filepath.Join(private, "home", "projects"), own} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", d, err)
		}
	}
	data, err := os.ReadFile(filepath.Join(home, ".claude.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read ~/.claude.json: %w", err)
	}
	if len(data) == 0 {
		data = []byte("{}\n")
	}
	data, err = claude.FilterMCPServers(data, s.req.Profile.Claude.MCPServers)
	if err != nil {
		return err
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
	for _, f := range s.req.Profile.Egress.Forwards() {
		out = append(out, fmt.Sprintf("%d=%s", f.Port, jail.InJail(fmt.Sprintf("port-%d.sock", f.Port))))
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

	forwards := s.forwards()
	command := s.req.Command
	var extra []jail.Bind
	if claude.Matches(command) {
		command = claude.Args(command, jail.InJail("claude-settings.json"))
		st := claude.State{Home: home, Cwd: s.req.Cwd, ShareLogin: s.req.Profile.Claude.ShareLogin, Private: filepath.Join(s.cacheRoot(), "claude", "home"), ConfigCopy: filepath.Join(s.cacheRoot(), "claude", "claude.json")}
		extra = append(extra, st.Binds(osHost{})...)
	}
	extra = append(extra, s.cloneBinds()...)
	argv := []string{jail.ExePath, "init", "--identify", strconv.Itoa(jail.ProxyPort)}
	for _, f := range forwards {
		argv = append(argv, "--forward", f)
	}
	argv = append(argv, "--")
	if !p.Hardening.NoLandlock {
		argv = append(argv, jail.ExePath, "sandbox-exec")
		for _, w := range s.writable(extra) {
			argv = append(argv, "--writable", w)
		}
		argv = append(argv, "--")
	}
	argv = append(argv, command...)

	return jail.Plan(p, s.layout(), jail.Options{
		Clones:     s.cloneDirs(),
		InfoFD:     3,
		SeccompFD:  4,
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
	infoR, infoW, err := os.Pipe()
	if err != nil {
		return 1, err
	}
	filter, err := s.seccompFile()
	if err != nil {
		_ = infoR.Close()
		_ = infoW.Close()
		return 1, err
	}
	defer filter.Close()
	cmd.ExtraFiles = []*os.File{infoW, filter}
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTSTP)
	defer signal.Reset(syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTSTP)
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		_ = infoW.Close()
		_ = infoR.Close()
		return 1, fmt.Errorf("start bubblewrap: %w", err)
	}
	_ = infoW.Close()
	go func() {
		defer infoR.Close()
		if info, err := readInfo(infoR, time.Minute); err == nil {
			s.peers.setInit(info.ChildPID)
		}
	}()
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
	err = cmd.Wait()
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
	s.log.Write("session-end", map[string]any{"exit": code, "denied": s.egress.Denials()})
	for _, line := range s.landClones(context.Background()) {
		fmt.Fprintln(s.deps.Stderr, line)
	}
	if line := Summary(s.req.Profile.Name, s.id, s.egress.Denials(), s.manager.History()); line != "" {
		fmt.Fprintln(s.deps.Stderr, line)
	}
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

func (osHost) Resolve(p string) (string, error) { return filepath.EvalSymlinks(p) }

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

// writable lists where the agent may write under Landlock: everything the
// jail mounts read-write, plus the jail's own scratch locations.
func (s *Session) writable(extra []jail.Bind) []string {
	p := s.req.Profile
	home := s.deps.Paths.Home
	out := []string{home, "/tmp", "/var/tmp", "/dev", "/proc", filepath.Join("/run/user", strconv.Itoa(os.Getuid()))}
	for _, m := range p.Mounts {
		if m.Mode == profile.ModeReadWrite || m.Mode == profile.ModeClone {
			out = append(out, m.Path)
		}
	}
	for _, c := range p.Caches {
		out = append(out, c.Path)
	}
	for _, b := range extra {
		if !b.ReadOnly && !b.Device {
			out = append(out, b.Dest)
		}
	}
	return out
}

// seccompFile holds the agent jail's seccomp program for bubblewrap.
func (s *Session) seccompFile() (*os.File, error) {
	arch, err := seccomp.HostArch()
	if err != nil {
		return nil, err
	}
	h := s.req.Profile.Hardening
	prog, err := seccomp.Build(arch, seccomp.Policy{AllowNamespaces: h.Namespaces, AllowPtrace: h.Ptrace})
	if err != nil {
		return nil, fmt.Errorf("build seccomp filter: %w", err)
	}
	path := filepath.Join(s.dir, "seccomp.bpf")
	if err := writeFile(path, prog, 0o600); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open seccomp filter: %w", err)
	}
	return f, nil
}
