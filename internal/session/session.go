// Package session runs one agent inside a jail, with the proxy, broker,
// approvals and signing agent that serve it.
package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fnune/doriath/internal/agents"
	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/audit"
	"github.com/fnune/doriath/internal/ca"
	"github.com/fnune/doriath/internal/clipboard"
	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/containers"
	"github.com/fnune/doriath/internal/jail"
	"github.com/fnune/doriath/internal/jailinit"
	"github.com/fnune/doriath/internal/oauth"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/promote"
	"github.com/fnune/doriath/internal/proxy"
	"github.com/fnune/doriath/internal/seccomp"
	"github.com/fnune/doriath/internal/secret"
	"github.com/fnune/doriath/internal/sshagent"
	"github.com/fnune/doriath/internal/term"
	"github.com/fnune/doriath/internal/termbar"
	"github.com/fnune/doriath/internal/vcs"
	"github.com/fnune/doriath/internal/vcstools"
)

const (
	ProxySocket   = "proxy.sock"
	BrokerSocket  = "broker.sock"
	AgentSocket   = "ssh-agent.sock"
	PodmanSocket  = "podman.sock"
	ControlSocket = "control.sock"
	InfoFile      = "session.json"
)

// Informer shows a message that needs no decision.
type Informer interface {
	Inform(session, title, body string) error
}

// Secrets serves the profile's secrets, and tells which ones it could not
// read.
type Secrets interface {
	secret.Store
	Unavailable() map[string]error
	Provide(name string, v secret.Value) error
	Retry(name string)
}

type Deps struct {
	Paths    config.Paths
	User     config.User
	Secrets  Secrets
	Notifier approval.Notifier
	Informer Informer
	Clock    approval.Clock
	// Dialer reaches upstream hosts. With a Resolver set, it is wrapped so
	// the proxy cannot reach loopback, link-local or unnamed private
	// addresses. LocalDialer reaches the forwarded host ports.
	Dialer      proxy.Dialer
	Resolver    Resolver
	LocalDialer proxy.Dialer
	Getenv      func(string) string
	Environ     []string
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	// Bwrap is the bubblewrap binary.
	Bwrap string
	// Exe is doriath's own binary, which runs as init inside the jail.
	Exe string
	// VCS are the version control tools the jail configures.
	VCS []vcstools.Tool
	// Unshare and Nsenter are util-linux tools for the podman service and
	// for joining its network namespace. Podman is the podman binary.
	Unshare string
	Nsenter string
	Podman  string
	Git     string
	// HostWait is how long a refused request waits for your decision
	// before the agent gets an error. The request stays pending after.
	HostWait time.Duration
	// ToolWait is how long an agent's permission prompt waits in doriath's
	// queue before the agent shows its own.
	ToolWait time.Duration
	// JJ records and restores bookmarks of jj repositories that are not
	// colocated with git. Empty skips them.
	JJ string
	// SystemdRun puts each jail in a systemd user scope with the profile's
	// limits. Empty runs without limits.
	SystemdRun string
	// UpstreamRoots verifies upstream servers in tests. Nil means the system
	// roots.
	UpstreamRoots *x509.CertPool
	// Promote makes a path writable in the running jail.
	Promote func(context.Context, promote.Request) error
	// Interrupted runs the end step of the sessions that ended without one
	// and used one of the git stores. It returns a note for each other such
	// session.
	Interrupted func(ctx context.Context, stores []string) []string
	// Read shows a host directory read-only in the running jail.
	Read func(context.Context, promote.Request) error
	Open func(url string) error
	// Clipboard is your clipboard, for profiles that let the agent ask for
	// its images. Nil when doriath runs outside a desktop session.
	Clipboard clipboard.Source
}

type Request struct {
	Profile *profile.Profile
	// Cwd is where the command starts in the jail.
	Cwd string
	// Current is {current}: the directory the session is for. Empty means
	// Cwd.
	Current string
	Command []string
	// Learn lets egress reach any public host and reports the hosts the
	// profile does not allow when the session ends.
	Learn bool
}

// Info describes a running session for doriath approvals and doriath status.
type Info struct {
	ID      string    `json:"id"`
	Profile string    `json:"profile"`
	Cwd     string    `json:"cwd"`
	Command []string  `json:"command"`
	PID     int       `json:"pid"`
	Started time.Time `json:"started"`
}

type Session struct {
	links   *linkKeeper
	deps    Deps
	req     Request
	id      string
	dir     string
	jailDir string
	log     *audit.Log
	egress  *egressLog
	policy  *livePolicy
	peers   *hostPeers
	logFile io.Closer
	repos   repositoryRecord
	notes   []note
	manager *approval.Manager
	informs informLimit
	closers []func()
	entry   Entry

	agent    agents.Adapter
	command  []string
	agentEnv map[string]string
	placed   []jail.Bind
	// etcOverlay holds files that appear in the jail's /etc, which the root
	// bind makes read-only so that no bind can create a file there.
	etcOverlay string
	netnsPID   int

	repository          string
	containerBroker     *containers.Broker
	unresolved          *profile.Profile
	modulesByRepository map[string][]string

	mu               sync.Mutex
	listings         *listingCache
	dismissedSecrets map[string]bool
	hostForwards     map[int]*hostForward
	hostConnects     map[int]*hostConnect
	vcsEnv           map[string]string
	// clipboardEnv points clipboard tools at the jail's Wayland display.
	clipboardEnv map[string]string
	roots        *vcs.RootGuard
	rootLog      *repairLog
	titled       bool
}

func New(deps Deps, req Request) (*Session, error) {
	if req.Current == "" {
		req.Current = req.Cwd
	}
	exists := func(p string) bool { return osHost{}.Kind(p) != "" }
	unresolved := req.Profile
	repository := profile.FindRepository(req.Current, exists)
	resolved, err := req.Profile.Resolve(profile.Start{Current: req.Current, Repository: repository, Exists: exists}, deps.Paths.Home)
	if err != nil {
		return nil, fmt.Errorf("profile %s: %w", req.Profile.Name, err)
	}
	listings := newListingCache()
	stopNote := noteIfSlow(deps.Stderr, slowWalk, "looking for git and jj repositories in the profile's mounts; a mount that holds many checkouts slows the start")
	req.Profile = refuseOwnLogins(withLinkedStores(resolved, listings), deps.Paths.State)
	stopNote()
	if err := CheckSigning(req.Profile, deps.VCS); err != nil {
		return nil, err
	}
	if err := checkHelpers(deps, req.Profile); err != nil {
		return nil, err
	}
	id, err := newID(deps.Paths)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(deps.Paths.Sessions(), id)
	exe, err := filepath.EvalSymlinks(deps.Exe)
	if err != nil {
		exe = deps.Exe
	}
	return &Session{deps: deps, req: req, id: id, dir: dir, jailDir: filepath.Join(dir, "jail"), peers: newHostPeers(exe), repository: repository, unresolved: unresolved, modulesByRepository: map[string][]string{}, listings: listings, dismissedSecrets: map[string]bool{}}, nil
}

func (s *Session) ID() string { return s.id }

// Run prepares the jail, runs the command in it and returns its exit code.
func (s *Session) Run(ctx context.Context) (int, error) {
	defer s.cleanup()
	s.titled = s.deps.User.Terminal.Title && term.IsTerminal(s.deps.Stderr)
	if err := s.prepare(ctx); err != nil {
		return 1, err
	}
	spec, err := s.plan()
	if err != nil {
		return 1, err
	}
	if err := s.links.Keep(spec.Links...); err != nil {
		return 1, err
	}
	notes := spec.Notes
	if s.deps.SystemdRun == "" {
		notes = append(notes, "systemd-run is not available, so this session runs without the profile's task and memory limits")
	}
	for _, n := range notes {
		s.notes = append(s.notes, note{term.Warn, n})
	}
	if len(s.notes) > 0 {
		if summary := s.secretsStatus().SecretsSummary(noteWidth(s.deps.Stderr)); summary != "" {
			s.notes = append(s.notes, note{term.Info, summary})
		}
	}
	printBlock(term.New(s.deps.Stderr), s.notes, s.req.Profile.Name, "session "+s.id)
	if s.titled {
		restore := term.Title(s.deps.Stderr, "doriath · "+s.req.Profile.Name)
		defer restore()
	}
	return s.exec(ctx, spec)
}

func (s *Session) prepare(ctx context.Context) error {
	p := s.req.Profile
	if err := os.MkdirAll(s.layout().EmptyDir(), 0o700); err != nil {
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
	s.links = newLinkKeeper(s.linkRestored)
	s.closers = append(s.closers, s.links.Close, s.stopForwards, s.stopConnects)
	s.policy = newLivePolicy(p, s.req.Learn)
	if s.req.Learn {
		s.notes = append(s.notes, note{term.Warn, "learning mode: any public host is reachable this session, and doriath lists the ones the profile does not allow when it ends"})
	}
	s.manager = approval.NewManager(s.deps.Clock, s.deps.Notifier, s.log, randomIDs{})

	for _, d := range []string{s.cacheRoot(), s.tmp(), s.scratchHome()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", d, err)
		}
	}
	s.closers = append(s.closers, func() { _ = os.RemoveAll(s.tmp()) }, func() { _ = os.RemoveAll(s.scratchHome()) })
	for _, c := range p.Caches {
		if err := os.MkdirAll(jail.CacheSource(s.cacheRoot(), c.Path, s.deps.Paths.Home), 0o700); err != nil {
			return fmt.Errorf("create cache for %s: %w", c.Path, err)
		}
	}

	for _, m := range p.Mounts {
		if m.Create {
			if err := jail.CheckLinks(p, osHost{}, m.Path); err != nil {
				return err
			}
			if err := os.MkdirAll(m.Path, 0o755); err != nil {
				return fmt.Errorf("create %s: %w", m.Path, err)
			}
		}
	}
	if err := s.fetchSecrets(ctx); err != nil {
		return err
	}
	if err := s.holdMissingPaths(p); err != nil {
		return err
	}
	if err := s.guardMissingHolds(p); err != nil {
		s.notes = append(s.notes, note{term.Warn, err.Error()})
	}
	s.rootLog = &repairLog{log: s.log}
	roots, err := vcs.NewRootGuard(s.rootLog)
	if err != nil {
		s.notes = append(s.notes, note{term.Warn, fmt.Sprintf("doriath removes a commondir that the agent writes into a repository's store only when the session ends: %v", err)})
	}
	s.roots = roots
	s.closers = append(s.closers, roots.Close)
	if err := s.holdControlPaths(); err != nil {
		return err
	}
	if err := s.startRepositories(ctx); err != nil {
		return err
	}
	var pinNotes []string
	s.peers.pins, pinNotes = pinBinaries(p, s.deps.Paths.Home, s.cacheRoot(), agentWritable(s.deps, p))
	pinNotes = append(pinNotes, s.peers.pins.pinLibraries(p, s.deps.Paths.Home, s.cacheRoot(), agentWritable(s.deps, p))...)
	var archiveNotes []string
	s.peers.pins.archives, archiveNotes = pinArchives(p, s.deps.Paths.Home, s.cacheRoot(), "/proc", agentWritable(s.deps, p))
	s.peers.pins.archives.hostPID = func(jailPID int) (int, error) {
		return hostPID("/proc", s.peers.reaper(), jailPID)
	}
	for _, n := range append(pinNotes, archiveNotes...) {
		s.notes = append(s.notes, note{term.Warn, n})
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
	if err := s.startClipboard(ctx); err != nil {
		return err
	}
	if p.Podman {
		if err := s.startPodman(); err != nil {
			return err
		}
	}
	if err := s.writeVCSFiles(); err != nil {
		return err
	}
	if err := s.writeMCPConfig(); err != nil {
		return err
	}
	if err := s.writeInstructions(); err != nil {
		return err
	}
	s.command = s.req.Command
	var warning string
	if s.agent, warning = adapterFor(s.req.Profile, s.req.Command); s.agent != nil {
		if err := agents.Plant(s.agent.Seeds(s.agentSession())); err != nil {
			return err
		}
		command, env, err := s.agent.Start(s.agentSession(), s.req.Command)
		if err != nil {
			return err
		}
		s.command, s.agentEnv = command, env
	}
	if warning != "" {
		s.notes = append(s.notes, note{term.Warn, warning})
	}
	return s.writeInfo()
}

func (s *Session) addCloser(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closers = append(s.closers, f)
}

func (s *Session) cacheRoot() string   { return s.deps.Paths.AgentCache(s.req.Profile.StateName()) }
func (s *Session) tmp() string         { return filepath.Join(s.cacheRoot(), "tmp", s.id) }
func (s *Session) scratchHome() string { return filepath.Join(s.cacheRoot(), "scratch", s.id) }
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
	store, err := JavaTrustStore(bundle)
	if err != nil {
		return err
	}
	if err := writeFile(s.jailPath("truststore.p12"), store, 0o644); err != nil {
		return err
	}
	if slices.Contains(p.Modules, "bazel") {
		if err := s.writeBazelRC(); err != nil {
			return err
		}
	}
	srv := proxy.New(proxy.Config{
		Session:       s.id,
		Profile:       p.Name,
		ApprovalTTL:   approvalTTL,
		UpstreamRoots: s.deps.UpstreamRoots,
		Holder:        s,
		Waiting:       s,
		WaitingAfter:  waitHintAfter,
	}, s.policy, s.manager, carding{s}, issuer, s.upstreamDialer(), s.egress)
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
	go s.relayToHost(ctx, l, f.Port)
	return nil
}

// relayToHost passes each connection on l to a port of the loopback address
// of your machine.
func (s *Session) relayToHost(ctx context.Context, l net.Listener, port int) {
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			up, err := s.localDialer().DialContext(ctx, "tcp", target)
			if err != nil {
				s.egress.Egress(proxy.Event{Kind: "error", Host: "127.0.0.1", Port: strconv.Itoa(port), Reason: err.Error()})
				return
			}
			defer up.Close()
			splice(conn, up)
		}()
	}
}

func (s *Session) httpForward(target string, port int) http.Handler {
	transport := &http.Transport{DialContext: s.localDialer().DialContext, MaxIdleConnsPerHost: 8, IdleConnTimeout: 90 * time.Second}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = target
		},
		Transport:     transport,
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.egress.Egress(proxy.Event{Kind: "error", Host: "127.0.0.1", Port: strconv.Itoa(port), Method: r.Method, Path: r.URL.Path, Reason: err.Error()})
			http.Error(w, fmt.Sprintf("doriath: nothing answers on port %d: %v", port, err), http.StatusBadGateway)
		},
	}
	var seen sync.Once
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Do(func() { s.egress.Egress(proxy.Event{Kind: "port", Host: "127.0.0.1", Port: strconv.Itoa(port)}) })
		rp.ServeHTTP(w, r)
	})
}

func (s *Session) fetchSecrets(ctx context.Context) error {
	p := s.req.Profile
	for _, name := range slices.Sorted(maps.Keys(p.Secrets)) {
		if p.Secrets[name].OAuth != nil && s.signedIn(name) {
			continue
		}
		_, err := s.deps.Secrets.Get(ctx, name)
		switch {
		case err == nil:
		case p.Secrets[name].Required:
			return secret.Explained(err)
		default:
			s.notes = append(s.notes, note{term.Warn, fmt.Sprintf("%v. The session starts without it: %s", secret.Explained(err), strings.Join(secretUsers(p, name), ", "))})
		}
	}
	return nil
}

func (s *Session) signedIn(secret string) bool {
	_, err := os.Stat(oauth.StatePath(s.deps.Paths.State, s.req.Profile.SecretOwner(secret), secret))
	return !errors.Is(err, os.ErrNotExist)
}

func secretUsers(p *profile.Profile, name string) []string {
	var users []string
	for _, h := range p.HTTP {
		uses := h.Credential != nil && h.Credential.Secret == name
		for _, r := range h.Rules {
			uses = uses || r.Credential != nil && r.Credential.Secret == name
		}
		if uses {
			users = append(users, "requests to "+string(h.Host))
		}
	}
	for _, m := range p.MCP {
		if m.Secret == name {
			users = append(users, "the MCP server "+m.Name)
		}
	}
	if len(users) == 0 {
		users = append(users, "nothing in the profile uses it")
	}
	return users
}

func (s *Session) startSigning(context.Context) error {
	p := s.req.Profile
	if p.SigningKey == "" {
		return nil
	}
	key, err := s.deps.Secrets.Get(context.Background(), p.SigningKey)
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	a, err := sshagent.New(key.Reveal(), "doriath "+p.Name, []string{"git"})
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

// JJGit is the name the doriath binary answers to as the git that jj runs,
// and FrontsDir the directory of the session's own commands, which the jail
// puts first on PATH: the doriath binary answers to the name of each.
const (
	JJGit     = "jj-git"
	FrontsDir = "bin"
	OpenFront = "xdg-open"
)

func (s *Session) writeVCSFiles() error {
	p := s.req.Profile
	if err := os.MkdirAll(s.jailPath(FrontsDir), 0o755); err != nil {
		return err
	}
	for _, link := range []string{JJGit, filepath.Join(FrontsDir, "git"), filepath.Join(FrontsDir, OpenFront)} {
		if err := os.Symlink(jail.ExePath, s.jailPath(link)); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	j := vcstools.Jail{Path: jail.InJail, SSHCommand: jail.ExePath + " __ssh", JJGit: jail.InJail(JJGit)}
	if p.SigningKey != "" {
		j.SigningKey = jail.InJail("signing.pub")
	}
	for _, h := range p.HTTP {
		if h.SSH != nil {
			j.RewriteSSH = append(j.RewriteSSH, vcstools.SSHRewrite{Host: string(h.Host), SSHHosts: h.SSH.Hosts, User: h.SSH.User, Port: h.SSH.Port})
		}
	}
	s.vcsEnv = map[string]string{}
	for _, t := range s.deps.VCS {
		c := t.Jail(j)
		for name, data := range c.Files {
			if err := writeFile(s.jailPath(name), data, 0o644); err != nil {
				return err
			}
		}
		maps.Copy(s.vcsEnv, c.Env)
	}
	return nil
}

// CheckSigning refuses a profile without a signing key when your git or jj
// signs every commit, since commits in the jail would then fail.
func CheckSigning(p *profile.Profile, tools []vcstools.Tool) error {
	if p.SigningKey != "" || p.Unsigned {
		return nil
	}
	for _, t := range tools {
		if setting := t.HostSigns(); setting != "" {
			return fmt.Errorf("profile %s: your %s signs commits (%s), but the profile has no signing key, so commits in the jail would fail. Add [signing] with a key for this profile, or set [signing] enable = false to commit unsigned", p.Name, t.Name(), setting)
		}
	}
	return nil
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
	return jail.Layout{JailDir: s.jailDir, CacheRoot: s.cacheRoot(), Tmp: s.tmp(), Home: s.scratchHome(), Exe: s.deps.Exe}
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
		"BROWSER":             jail.InJail(filepath.Join(FrontsDir, OpenFront)),
		"CURL_CA_BUNDLE":      jail.InJail("ca-bundle.pem"),
		"GIT_SSL_CAINFO":      jail.InJail("ca-bundle.pem"),
		"REQUESTS_CA_BUNDLE":  jail.InJail("ca-bundle.pem"),
		"AWS_CA_BUNDLE":       jail.InJail("ca-bundle.pem"),
		"NODE_EXTRA_CA_CERTS": jail.InJail("ca-bundle.pem"),
		"JAVA_TOOL_OPTIONS":   javaToolOptions(p.Env.Set["JAVA_TOOL_OPTIONS"]),
		"DORIATH_SESSION":     s.id,
		"DORIATH_BROKER":      jail.InJail(BrokerSocket),
	}
	maps.Copy(env, s.vcsEnv)
	maps.Copy(env, s.clipboardEnv)
	if p.SigningKey != "" {
		env["SSH_AUTH_SOCK"] = jail.InJail(AgentSocket)
	}
	if p.Podman {
		env["CONTAINER_HOST"] = "unix://" + jail.InJail(PodmanSocket)
		env["DOCKER_HOST"] = "unix://" + jail.InJail(PodmanSocket)
	}

	forwards := s.forwards()
	command := s.command
	for k, v := range s.agentEnv {
		env[k] = v
	}
	extra := slices.Clone(s.placed)
	argv := []string{jail.ExePath, "__init", "--identify", strconv.Itoa(jail.ProxyPort)}
	for _, f := range forwards {
		argv = append(argv, "--forward", f)
	}
	argv = append(argv, "--")
	s.entry = Entry{Cwd: s.req.Cwd, Landlock: !p.Hardening.NoLandlock, AgentWritable: agentWritable(s.deps, p)}
	if s.entry.Landlock {
		s.entry.Writable = s.writable(extra)
	}
	if !p.Hardening.NoLandlock {
		argv = append(argv, jail.ExePath, "__sandbox-exec")
		for _, w := range s.writable(extra) {
			argv = append(argv, "--writable", w)
		}
		argv = append(argv, "--")
	}
	argv = append(argv, command...)

	return jail.Plan(p, s.layout(), jail.Options{
		InfoFD:      3,
		SeccompFD:   4,
		SkipNetNS:   s.netnsPID != 0,
		SetIDs:      s.netnsPID != 0,
		GID:         os.Getgid(),
		UID:         os.Getuid(),
		Home:        home,
		Cwd:         s.req.Cwd,
		Command:     argv,
		HostEnv:     envMap(s.deps.Environ),
		ExtraEnv:    env,
		ExtraBinds:  extra,
		EtcOverlay:  s.etcOverlay,
		PathPrepend: []string{jail.InJail(FrontsDir)},
	}, s.listings)
}

const agentArgsFD = 5

const barSecretsWidth = 48

func (s *Session) barWanted() bool {
	_, inOK := s.deps.Stdin.(*os.File)
	out, outOK := s.deps.Stdout.(*os.File)
	return s.deps.User.Terminal.Bar && inOK && outOK && term.IsTerminal(out)
}

func (s *Session) openBar() (*termbar.Bar, error) {
	if !s.barWanted() {
		return nil, nil
	}
	bar, err := termbar.Open(s.deps.Stdin.(*os.File), s.deps.Stdout.(*os.File))
	if err != nil || bar == nil {
		return nil, err
	}
	bar.Set(s.status().Summary(barSecretsWidth))
	return bar, nil
}

func (s *Session) updateBar(bar *termbar.Bar, done <-chan struct{}) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			bar.Set(s.status().Summary(barSecretsWidth))
		case <-done:
			return
		}
	}
}

func (s *Session) terminalEnv() []string {
	command := filepath.Base(s.req.Command[0])
	var out []string
	for _, k := range slices.Sorted(maps.Keys(s.deps.User.Terminal.Env)) {
		out = append(out, k+"="+strings.ReplaceAll(s.deps.User.Terminal.Env[k], "{command}", command))
	}
	return out
}

func (s *Session) exec(ctx context.Context, spec jail.Spec) (int, error) {
	args, err := spec.ArgsFile()
	if err != nil {
		return 1, err
	}
	defer args.Close()
	bwrapArgs := spec.ArgsFrom(agentArgsFD)
	cmd := exec.Command(s.deps.Bwrap, bwrapArgs...)
	if s.netnsPID != 0 {
		if s.deps.Nsenter == "" {
			return 1, errors.New("joining the podman network namespace needs util-linux nsenter")
		}
		target := strconv.Itoa(s.netnsPID)
		cmd = exec.Command(s.deps.Nsenter, append([]string{"--target", target, "--user", "--net", "--", s.deps.Bwrap}, bwrapArgs...)...)
	}
	cmd = s.limited(cmd, "agent")
	cmd.Env = append(cmd.Env, s.terminalEnv()...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = s.deps.Stdin, s.deps.Stdout, s.deps.Stderr
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
	cmd.ExtraFiles = []*os.File{infoW, filter, args}
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTSTP)
	defer signal.Reset(syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTSTP)
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	bar, err := s.openBar()
	if err != nil {
		_ = infoW.Close()
		_ = infoR.Close()
		return 1, err
	}
	if bar != nil {
		defer func() { _ = bar.Close() }()
		err = bar.Start(cmd)
	} else {
		err = cmd.Start()
	}
	if err != nil {
		_ = infoW.Close()
		_ = infoR.Close()
		return 1, fmt.Errorf("start bubblewrap: %w", err)
	}
	_ = infoW.Close()
	go func() {
		defer infoR.Close()
		if info, err := readInfo(infoR, time.Minute); err == nil {
			s.peers.setInit(info.ChildPID)
			s.writeEntry(info.ChildPID, spec)
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
	if bar != nil {
		go s.updateBar(bar, done)
	}
	err = cmd.Wait()
	close(done)
	if bar != nil {
		_ = bar.Close()
	}
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
	t := term.New(s.deps.Stderr)
	var repos bytes.Buffer
	if s.roots != nil {
		s.roots.Close()
		_, _ = repos.Write(s.rootLog.lines.Bytes())
	}
	s.links.Check()
	s.finishRepositories(&repos)
	var end []note
	for _, line := range strings.Split(strings.TrimSpace(repos.String()), "\n") {
		if line != "" {
			end = append(end, note{term.Warn, Printable(line)})
		}
	}
	if s.agent != nil {
		if err := s.agent.End(s.agentSession()); err != nil {
			end = append(end, note{term.Problem, Printable(err.Error())})
		}
	}
	if learned := s.policy.Learned(); len(learned) > 0 {
		by := s.policy.LearnedBy()
		s.log.Write("learned", map[string]any{"hosts": learned, "by_program": by})
		text := fmt.Sprintf("reached %d hosts that the profile does not allow", len(learned))
		for _, prog := range slices.Sorted(maps.Keys(by)) {
			text += fmt.Sprintf("\n%s: %s", PrintableLine(prog), PrintableLine(strings.Join(by[prog], " ")))
		}
		text += "\nTo allow them, add to profile " + s.req.Profile.Name + ", or under [[egress.programs]] for one program only:\n" + egressLines(learned)
		end = append(end, note{term.Info, text})
	}
	if large := largeScratchFolders(s.scratchHome()); len(large) > 0 {
		end = append(end, note{term.Info, scratchNote(large, s.req.Profile.Name)})
	}
	end = append(end, summary(s.egress.Denials(), s.manager.History())...)
	if len(end) > 0 {
		end = append(end, note{term.Info, t.Dim("details: doriath log --session " + s.id)})
	}
	printBlock(t, end, s.req.Profile.Name, "session "+s.id+" ended")
	return code, nil
}

func (s *Session) cleanup() {
	s.mu.Lock()
	closers := slices.Clone(s.closers)
	s.mu.Unlock()
	for i := len(closers) - 1; i >= 0; i-- {
		closers[i]()
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

type osHost struct{}

func (osHost) Entries(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return names
}

func (osHost) List(dir string) []jail.Entry {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make([]jail.Entry, len(entries))
	for i, e := range entries {
		out[i] = jail.Entry{Name: e.Name(), Dir: e.IsDir()}
	}
	return out
}

type listingCache struct {
	osHost
	mu    sync.Mutex
	lists map[string][]jail.Entry
}

func newListingCache() *listingCache {
	return &listingCache{lists: map[string][]jail.Entry{}}
}

func (c *listingCache) List(dir string) []jail.Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if l, ok := c.lists[dir]; ok {
		return l
	}
	l := c.osHost.List(dir)
	c.lists[dir] = l
	return l
}

const slowWalk = 2 * time.Second

func noteIfSlow(w io.Writer, after time.Duration, note string) (stop func()) {
	t := time.AfterFunc(after, func() { fmt.Fprintln(w, "doriath: "+note) })
	return func() { t.Stop() }
}

func (osHost) Link(p string) bool {
	info, err := os.Lstat(p)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}

func (osHost) Resolve(p string) string {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return ""
	}
	return real
}

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

func (s *Session) writable(extra []jail.Bind) []string {
	p := s.req.Profile
	home := s.deps.Paths.Home
	out := []string{home, "/tmp", "/var/tmp", "/dev", "/proc", filepath.Join("/run/user", strconv.Itoa(os.Getuid()))}
	for _, m := range p.Mounts {
		if m.Mode == profile.ModeWrite {
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

func (s *Session) upstreamDialer() proxy.Dialer {
	if s.deps.Resolver == nil {
		return s.deps.Dialer
	}
	return newGuardDialer(s.deps.Dialer, s.deps.Resolver, s.req.Profile)
}

func (s *Session) localDialer() proxy.Dialer {
	if s.deps.LocalDialer != nil {
		return s.deps.LocalDialer
	}
	return s.deps.Dialer
}

func (s *Session) limited(cmd *exec.Cmd, role string) *exec.Cmd {
	cmd.Env = []string{}
	lim := s.req.Profile.Limits
	if s.deps.SystemdRun == "" || (lim.Tasks == 0 && lim.Memory == "" && lim.CPU == "") {
		return cmd
	}
	args := []string{
		"--user", "--scope", "--quiet", "--collect",
		"--unit", fmt.Sprintf("doriath-%s-%s-%s", s.req.Profile.Label(), role, s.id),
	}
	if lim.Tasks > 0 {
		args = append(args, "-p", fmt.Sprintf("TasksMax=%d", lim.Tasks))
	}
	if lim.Memory != "" {
		args = append(args, "-p", "MemoryMax="+lim.Memory)
	}
	if lim.CPU != "" {
		args = append(args, "-p", "CPUQuota="+lim.CPU)
	}
	args = append(args, "--")
	args = append(args, cmd.Args...)
	wrapped := exec.Command(s.deps.SystemdRun, args...)
	wrapped.SysProcAttr = cmd.SysProcAttr
	for _, k := range userBusEnv {
		if v := s.deps.Getenv(k); v != "" {
			wrapped.Env = append(wrapped.Env, k+"="+v)
		}
	}
	if wrapped.Env == nil {
		wrapped.Env = []string{}
	}
	return wrapped
}

func agentWritable(deps Deps, p *profile.Profile) []string {
	writable := []string{deps.Paths.AgentCache(p.StateName())}
	for _, m := range p.Mounts {
		if m.Mode == profile.ModeWrite {
			writable = append(writable, m.Path)
		}
	}
	return writable
}

func checkHelpers(deps Deps, p *profile.Profile) error {
	writable := agentWritable(deps, p)
	helpers := []string{deps.Exe, deps.Bwrap, deps.Git, deps.JJ, deps.Unshare, deps.Nsenter, deps.Podman, deps.SystemdRun}
	for _, name := range slices.Sorted(maps.Keys(p.Secrets)) {
		if cmd := p.Secrets[name].Command; len(cmd) > 0 {
			if path, err := exec.LookPath(cmd[0]); err == nil {
				helpers = append(helpers, path)
			}
		}
	}
	for _, helper := range helpers {
		if err := checkHelper(helper, writable); err != nil {
			return err
		}
	}
	return nil
}

func checkHelper(helper string, writable []string) error {
	if helper == "" {
		return nil
	}
	real, err := filepath.EvalSymlinks(helper)
	if err != nil {
		real = helper
	}
	for _, w := range writable {
		if within(real, w) || within(helper, w) {
			return fmt.Errorf("%s is inside %s, which the jail can write: install it elsewhere or take it out of PATH", helper, w)
		}
	}
	return nil
}

// CheckHelper refuses a program on the host that the session's jail could
// have replaced.
func (e Entry) CheckHelper(helper string) error { return checkHelper(helper, e.AgentWritable) }

func within(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// EntryFile, in the session directory, tells doriath exec how to join the
// running jail.
const EntryFile = "entry.json"

// Entry is what a process needs to join a running jail as one of its own:
// the jail's first process to enter the namespaces of, and the environment
// and write rules the jail's processes have. The seccomp program sits next
// to it as seccomp.bpf.
type Entry struct {
	PID      int      `json:"pid"`
	UID      int      `json:"uid"`
	GID      int      `json:"gid"`
	Cwd      string   `json:"cwd"`
	Env      []string `json:"env"`
	Landlock bool     `json:"landlock"`
	Writable []string `json:"writable"`
	// AgentWritable are the host paths the agent can write and that
	// outlive the session: write mounts, grants and the profile's cache.
	AgentWritable []string `json:"agent_writable,omitempty"`
}

func (s *Session) writeEntry(pid int, spec jail.Spec) {
	for deadline := time.Now().Add(entryWait); !s.peers.initRunning(pid); {
		if time.Now().After(deadline) {
			s.log.Write("entry-error", map[string]string{"error": "the jail's init did not start"})
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entry.PID, s.entry.UID, s.entry.GID = pid, spec.UID, spec.GID
	for _, k := range slices.Sorted(maps.Keys(spec.Env)) {
		s.entry.Env = append(s.entry.Env, k+"="+spec.Env[k])
	}
	s.saveEntry()
}

func (s *Session) saveEntry() {
	data, err := json.Marshal(s.entry)
	if err == nil {
		err = writeFile(filepath.Join(s.dir, EntryFile), data, 0o600)
	}
	if err != nil {
		s.log.Write("entry-error", map[string]string{"error": err.Error()})
	}
}

func javaProperties() []string {
	port := strconv.Itoa(jail.ProxyPort)
	return []string{
		"-Djavax.net.ssl.trustStore=" + jail.InJail("truststore.p12"),
		"-Djavax.net.ssl.trustStoreType=PKCS12",
		"-Djavax.net.ssl.trustStorePassword=" + JavaTrustStorePassword,
		"-Dhttp.proxyHost=127.0.0.1", "-Dhttp.proxyPort=" + port,
		"-Dhttps.proxyHost=127.0.0.1", "-Dhttps.proxyPort=" + port,
		"-Dhttp.nonProxyHosts=localhost|127.0.0.1|[::1]",
	}
}

func javaToolOptions(profile string) string {
	opts := strings.Join(javaProperties(), " ")
	if profile != "" {
		return profile + " " + opts
	}
	return opts
}

const bazelSystemRC = "bazel.bazelrc"

// writeBazelRC puts the system rc in a directory that the jail overlays on
// /etc. Bazel reads that path in addition to the user's and the workspace's
// rc files, so a profile that mounts its own ~/.bazelrc keeps both.
func (s *Session) writeBazelRC() error {
	host, err := os.ReadFile(filepath.Join("/etc", bazelSystemRC))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read /etc/%s: %w", bazelSystemRC, err)
	}
	dir := s.jailPath("etc")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	s.etcOverlay = dir
	return writeFile(filepath.Join(dir, bazelSystemRC), BazelRC(host, javaProperties()), 0o644)
}

func shortPath(p string) string {
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(p, home+"/") {
		p = "~" + strings.TrimPrefix(p, home)
	}
	parts := strings.Split(p, "/")
	if len(parts) <= 4 {
		return p
	}
	return strings.Join(parts[:2], "/") + "/…/" + parts[len(parts)-1]
}

var userBusEnv = []string{"XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"}

const entryWait = 30 * time.Second
