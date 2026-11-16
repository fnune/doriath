//go:build integration

package session_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/bundle"
	"github.com/fnune/doriath/internal/ca"
	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/control"
	"github.com/fnune/doriath/internal/modules"
	"github.com/fnune/doriath/internal/notify"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/promote"
	"github.com/fnune/doriath/internal/secret"
	"github.com/fnune/doriath/internal/session"
	"github.com/fnune/doriath/internal/vcstools"
	gittool "github.com/fnune/doriath/internal/vcstools/git"
	jjtool "github.com/fnune/doriath/internal/vcstools/jj"
)

var doriathBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "doriath-it-")
	if err != nil {
		panic(err)
	}
	doriathBin = filepath.Join(dir, "doriath")
	out, err := exec.Command("go", "build", "-o", doriathBin, "github.com/fnune/doriath/cmd/doriath").CombinedOutput()
	if err != nil {
		panic(string(out))
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

type recorder struct {
	mu         sync.Mutex
	reqs       []*http.Request
	answerWith http.Handler
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	next := r.answerWith
	r.mu.Unlock()
	if next != nil {
		req.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, req)
		return
	}
	fmt.Fprintf(w, "upstream %s %s\n", req.Host, req.URL.Path)
}

func (r *recorder) find(path string) *http.Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, req := range r.reqs {
		if req.URL.Path == path {
			return req
		}
	}
	return nil
}

type proxyDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type redirect struct{ addr string }

func (d redirect) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var nd net.Dialer
	if strings.HasPrefix(address, "127.0.0.1:") {
		return nd.DialContext(ctx, network, address)
	}
	return nd.DialContext(ctx, network, d.addr)
}

type clock struct{}

func (clock) Now() time.Time                         { return time.Now() }
func (clock) After(d time.Duration) <-chan time.Time { return time.After(d) }

type env struct {
	t          *testing.T
	home       string
	work       string
	paths      config.Paths
	upstream   *recorder
	dialer     proxyDialer
	bundle     string
	secrets    map[string]secret.Backend
	roots      *ca.Authority
	binaries   string
	systemdRun string
	lastID     string

	cwd      string
	vcs      []vcstools.Tool
	hostWait time.Duration
	resolver session.Resolver
	agent    string
	modules  []string
	open     func(string) error
}

func newEnv(t *testing.T) *env {
	t.Helper()
	if _, err := exec.LookPath("bwrap"); err != nil && !bundle.Bundled() {
		t.Skip("bubblewrap not available")
	}
	root, err := os.MkdirTemp("/tmp", "gi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	// jj on the host keeps each repository's secure config there, where
	// the session finds it, and not in yours.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "host-config"))
	home := filepath.Join(root, "home")
	work := filepath.Join(home, "work")
	for _, d := range []string{filepath.Join(home, ".ssh"), work, filepath.Join(root, "run"), filepath.Join(root, "cfg", "profiles")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), []byte("PRIVATE"), 0o600); err != nil {
		t.Fatal(err)
	}

	upCA, err := ca.New([]string{"example.com", "api.github.com", "github.com", "drafted.example", "programs.example", "*.amazonaws.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	up := &recorder{}
	srv := httptest.NewUnstartedServer(up)
	srv.TLS = &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) { return upCA.Certificate(h.ServerName) }}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	system, err := os.ReadFile("/etc/ssl/certs/ca-certificates.crt")
	if err != nil {
		system = nil
	}
	bundlePath := filepath.Join(root, "bundle.pem")
	if err := os.WriteFile(bundlePath, append(system, upCA.CertPEM()...), 0o644); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(root, "token")
	if err := os.WriteFile(tokenPath, []byte("real-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &env{
		t:    t,
		home: home,
		work: work,
		paths: config.Paths{
			Home:    home,
			Config:  filepath.Join(root, "cfg"),
			State:   filepath.Join(root, "state"),
			Cache:   filepath.Join(root, "cache"),
			Runtime: filepath.Join(root, "run", "doriath"),
		},
		upstream: up,
		dialer:   redirect{addr: srv.Listener.Addr().String()},
		bundle:   bundlePath,
		roots:    upCA,
		secrets:  map[string]secret.Backend{"github": {File: tokenPath}},
	}
}

func (e *env) profile(extra string) *profile.Profile {
	e.t.Helper()
	quoted := make([]string, len(e.modules))
	for i, m := range e.modules {
		quoted[i] = fmt.Sprintf("%q", m)
	}
	listed := strings.Join(quoted, ", ")
	body := fmt.Sprintf(`
modules = [%s]

[[mounts]]
path = %q
mode = "write"

[egress]
allow = ["example.com"]

[[http]]
host = "api.github.com"
credential = { secret = "github", scheme = "bearer"%s }
# These tests exercise rules and injection, not the approve default that a
# credential otherwise brings.
default = "allow"

[[http.rules]]
method = "POST"
path = "/repos/*/*/releases"
action = "approve"
summary = "Create a GitHub release"
%s`, listed, e.work, e.binaries, extra)
	for _, name := range slices.Sorted(maps.Keys(e.secrets)) {
		body += fmt.Sprintf("\n[secrets.%s]\nfile = %q\nrequired = %t\n", name, e.secrets[name].File, e.secrets[name].Required)
	}
	if err := os.WriteFile(filepath.Join(e.paths.Profiles(), "it.toml"), []byte(body), 0o600); err != nil {
		e.t.Fatal(err)
	}
	l := &profile.Loader{Profiles: os.DirFS(e.paths.Profiles()), Modules: []fs.FS{modules.FS}, Home: e.home, Builtins: modules.Builtins}
	p, err := l.Load("it")
	if err != nil {
		e.t.Fatal(err)
	}
	p.PathRules.Warn = slices.DeleteFunc(p.PathRules.Warn, func(w profile.PathWarning) bool { return strings.HasPrefix(e.home, w.Path+"/") })
	return p
}

func (e *env) run(p *profile.Profile, script string, while func()) (int, string) {
	e.t.Helper()
	code, out, err := e.start(p, script, while)
	if err != nil {
		e.t.Fatalf("session: %v\n%s", err, out)
	}
	return code, out
}

func (e *env) start(p *profile.Profile, script string, while func()) (int, string, error) {
	e.t.Helper()
	scriptPath := filepath.Join(e.work, "script.sh")
	if e.agent != "" {
		scriptPath = filepath.Join(e.work, e.agent)
	}
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\n"+script), 0o700); err != nil {
		e.t.Fatal(err)
	}
	bwrap, err := bundle.Bwrap(e.paths.Bundle(), os.Getenv)
	if err != nil {
		e.t.Fatal(err)
	}
	var out bytes.Buffer
	getenv := func(k string) string {
		switch k {
		case "SSL_CERT_FILE":
			return e.bundle
		case "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS":
			return os.Getenv(k)
		}
		return ""
	}
	if e.vcs == nil {
		e.vcs = []vcstools.Tool{gittool.New(nil, nil), jjtool.New(e.home, func(string) string { return "" })}
	}
	deps := session.Deps{
		VCS:           e.vcs,
		Paths:         e.paths,
		Secrets:       secret.NewConfigured(p.Secrets, nil, secret.OSFiles{}),
		Notifier:      notify.None{},
		Informer:      notify.None{},
		Clock:         clock{},
		Dialer:        e.dialer,
		UpstreamRoots: e.rootPool(),
		Getenv:        getenv,
		Environ:       []string{"PATH=" + testPath(), "TERM=dumb", "GH_TOKEN=leak", "SSH_AUTH_SOCK=/run/user/1000/ssh-agent"},
		Stdin:         strings.NewReader(""),
		Stdout:        &out,
		Stderr:        &out,
		Bwrap:         bwrap,
		Exe:           doriathBin,
		Unshare:       lookPath("unshare"),
		Nsenter:       lookPath("nsenter"),
		Podman:        lookPath("podman"),
		Git:           lookPath("git"),
		JJ:            lookPath("jj"),
		HostWait:      e.hostWait,
		SystemdRun:    e.systemdRun,
		Resolver:      e.resolver,
		Promote:       promote.Writable,
		Read:          promote.Readable,
		Open:          e.open,
	}
	cwd := e.work
	if e.cwd != "" {
		cwd = e.cwd
	}
	s, err := session.New(deps, session.Request{Profile: p, Cwd: cwd, Command: []string{scriptPath}})
	if err != nil {
		e.t.Fatal(err)
	}
	e.lastID = s.ID()
	done := make(chan struct{})
	if while != nil {
		go func() {
			defer close(done)
			while()
		}()
	} else {
		close(done)
	}
	code, err := s.Run(context.Background())
	<-done
	return code, out.String(), err
}

func testPath() string {
	path := "/usr/bin:/bin"
	if p := lookPath("podman"); p != "" {
		if real, err := filepath.EvalSymlinks(p); err == nil {
			path = filepath.Dir(real) + ":" + path
		}
	}
	return path
}

func (e *env) rootPool() *x509.CertPool {
	if e.roots == nil {
		return nil
	}
	return e.roots.Pool()
}

func lookPath(name string) string {
	p, _ := exec.LookPath(name)
	return p
}

func (e *env) decideNext(d approval.Decision) approval.Request {
	e.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		matches, _ := filepath.Glob(filepath.Join(e.paths.Sessions(), "*", session.ControlSocket))
		for _, sock := range matches {
			var reqs []approval.Request
			if control.Call(context.Background(), sock, session.MethodList, struct{}{}, &reqs) == nil && len(reqs) > 0 {
				if err := control.Call(context.Background(), sock, session.MethodDecide, session.DecideParams{ID: reqs[0].ID, Decision: d}, nil); err != nil {
					e.t.Errorf("decide: %v", err)
				}
				return reqs[0]
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	e.t.Error("no request to decide")
	return approval.Request{}
}

func TestIsolation(t *testing.T) {
	e := newEnv(t)
	code, out := e.run(e.profile(""), `
test -e "$HOME/.ssh" && echo "FAIL ssh visible"
test -z "$(ls -A /run/user/$(id -u))" || echo "FAIL runtime dir not empty"
test -n "$GH_TOKEN" && test "$GH_TOKEN" = leak && echo "FAIL GH_TOKEN leaked"
grep -q "BEGIN CERTIFICATE" "$NODE_EXTRA_CA_CERTS" || echo "FAIL NODE_EXTRA_CA_CERTS holds no certificate"
test -e "$HOME/.bazelrc" && echo "FAIL bazelrc without the bazel module"
test -e /etc/bazel.bazelrc && echo "FAIL system bazelrc without the bazel module"
test -s /run/doriath/truststore.p12 || echo "FAIL no Java trust store"
test -n "$SSH_AUTH_SOCK" && echo "FAIL ssh agent leaked"
test -n "$DBUS_SESSION_BUS_ADDRESS" && echo "FAIL session bus"
ls /run/doriath/token* 2>/dev/null && echo "FAIL token file"
grep -r real-token /run/doriath 2>/dev/null && echo "FAIL token in doriath dir"
echo x > /run/doriath/probe 2>/dev/null && echo "FAIL doriath dir writable"
echo ok > "$PWD/written" || echo "FAIL worktree not writable"
echo done
exit 4
`, nil)
	if code != 4 || !strings.Contains(out, "done") || strings.Contains(out, "FAIL") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(e.work, "written")); err != nil {
		t.Fatal("the worktree write did not reach the host")
	}
}

func TestBazelModuleWritesTheSystemRC(t *testing.T) {
	e := newEnv(t)
	e.modules = []string{"bazel"}
	code, out := e.run(e.profile(""), `
for want in javax.net.ssl.trustStore=/run/doriath/truststore.p12 https.proxyHost=127.0.0.1 https.proxyPort=3128; do
  grep -q "startup --host_jvm_args=-D$want" /etc/bazel.bazelrc || echo "FAIL no $want"
done
test -e "$HOME/.bazelrc" && echo "FAIL home bazelrc"
echo x > /etc/bazel.bazelrc 2>/dev/null && echo "FAIL system bazelrc writable"
echo x > /etc/other 2>/dev/null && echo "FAIL etc writable"
test -e /etc/passwd || echo "FAIL etc lost its files"
echo done
exit 4
`, nil)
	if code != 4 || !strings.Contains(out, "done") || strings.Contains(out, "FAIL") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}

func TestEgressAndInjection(t *testing.T) {
	e := newEnv(t)
	code, out := e.run(e.profile(""), `
curl -sS -o /dev/null -w "tunnel %{http_code}\n" https://example.com/t
curl -sS -o /dev/null -H "Accept: text/markdown" https://example.com/markdown
curl -sS -o /dev/null -w "denied %{http_code}\n" https://example.org/ 2>/dev/null || true
curl -sS -H "Authorization: token $GH_TOKEN" -H "Accept: text/markdown" -o /dev/null -w "api %{http_code}\n" https://api.github.com/user
curl -sS -m 3 --noproxy '*' https://example.com/ >/dev/null 2>&1 && echo "FAIL direct network"
exit 0
`, nil)
	if code != 0 {
		t.Fatalf("code %d:\n%s", code, out)
	}
	for _, want := range []string{"tunnel 200", "api 200"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "FAIL") || !strings.Contains(out, "denied") || strings.Contains(out, "denied 200") {
		t.Errorf("output:\n%s", out)
	}
	if md := e.upstream.find("/markdown"); md == nil || md.Header.Get("Accept") != "text/markdown" {
		t.Errorf("content negotiation must reach the site as sent: %+v", md)
	}
	req := e.upstream.find("/user")
	if req == nil || req.Header.Get("Authorization") != "Bearer real-token" || req.Header.Get("Accept") != "text/markdown" {
		t.Fatalf("upstream request: %+v", req)
	}
	audit, _ := os.ReadFile(e.paths.AuditLog())
	if !strings.Contains(string(audit), `"host":"example.org"`) {
		t.Errorf("the denial is not in the audit log:\n%s", audit)
	}
	if strings.Contains(string(audit), "real-token") {
		t.Error("the token leaked into the audit log")
	}
}

func TestApprovals(t *testing.T) {
	e := newEnv(t)
	script := `
curl -sS -X POST -d '{}' https://api.github.com/repos/acme/app/releases
echo
curl -sS -X POST -d '{}' https://api.github.com/repos/acme/app/releases
echo
curl -sS -X POST -d '{}' https://api.github.com/repos/acme/app/releases
`
	var first approval.Request
	code, out := e.run(e.profile(""), script, func() {
		first = e.decideNext(approval.Decision{Verdict: approval.VerdictDeny, By: "test"})
		e.decideNext(approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession, By: "test"})
	})
	if code != 0 {
		t.Fatalf("code %d:\n%s", code, out)
	}
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) != "" && !strings.HasPrefix(l, "doriath") && !strings.HasPrefix(l, "  ") {
			lines = append(lines, l)
		}
	}
	if len(lines) != 3 || !strings.Contains(lines[0], "Create a GitHub release was denied") || !strings.Contains(lines[1], "upstream") || !strings.Contains(lines[2], "upstream") {
		t.Fatalf("output:\n%s", out)
	}
	if first.Summary != "Create a GitHub release" || first.Kind != approval.KindHTTP {
		t.Errorf("request = %+v", first)
	}
}

func TestClaudeHookThroughBroker(t *testing.T) {
	e := newEnv(t)
	script := `printf '%s' '{"tool_name":"Bash","tool_input":{"command":"gh release create v1","description":"Create release"}}' | /run/doriath-bin/doriath __hook claude permission-request --timeout 30s`
	var req approval.Request
	code, out := e.run(e.profile(""), script, func() {
		req = e.decideNext(approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingOnce, By: "test"})
	})
	if code != 0 || !strings.Contains(out, `"behavior":"allow"`) {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if req.Summary != "Run a command" || req.Note != "Create release" || req.Details != "gh release create v1" || req.Agent != "claude" {
		t.Errorf("request = %+v", req)
	}
}

func signingKey(t *testing.T) []byte {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

func TestGitSigningAndGuards(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	e := newEnv(t)
	keyPath := filepath.Join(filepath.Dir(e.home), "agent-key")
	if err := os.WriteFile(keyPath, signingKey(t), 0o600); err != nil {
		t.Fatal(err)
	}
	e.secrets["agent-key"] = secret.Backend{File: keyPath}
	if out, err := exec.Command("git", "init", "-q", e.work).CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
	p := e.profile("\n[signing]\nkey = \"agent-key\"\n")
	code, out := e.run(p, `
git config --global user.name test >/dev/null 2>&1
git -c user.name=Agent -c user.email=a@example.org commit -q --allow-empty -m signed || echo "FAIL commit"
git cat-file commit HEAD | grep -q gpgsig || echo "FAIL unsigned"
echo "[core]" >> .git/config 2>/dev/null && echo "FAIL git config writable"
touch .git/hooks/pre-commit 2>/dev/null && echo "FAIL hooks writable"
printf x > msg; ssh-keygen -Y sign -n file -f /run/doriath/signing.pub msg >/dev/null 2>&1 && echo "FAIL signed outside git namespace"
ssh-add -L | grep -q doriath || echo "FAIL agent key missing"
echo done
`, nil)
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "done") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}

func TestPortForward(t *testing.T) {
	e := newEnv(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "dev server") })}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	port := l.Addr().(*net.TCPAddr).Port
	p := e.profile("")
	p.Egress.Ports = []int{port}
	code, out := e.run(p, fmt.Sprintf("curl -sS http://127.0.0.1:%d/\n", port), nil)
	if code != 0 || !strings.Contains(out, "dev server") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}

func TestPodman(t *testing.T) {
	if lookPath("podman") == "" || lookPath("unshare") == "" || lookPath("nsenter") == "" {
		t.Skip("podman, unshare or nsenter missing")
	}
	e := newEnv(t)
	t.Cleanup(func() {
		if err := session.RemoveAsMapped(context.Background(), lookPath("unshare"), filepath.Join(e.paths.Cache, "agents")); err != nil {
			t.Log(err)
		}
	})
	p := e.profile("")
	p.Podman = true
	code, out := e.run(p, `
id -u; echo "PATH=$PATH"; ls -la $(echo $PATH | cut -d: -f1) | head -3
podman --remote info --format '{{.Store.GraphRoot}}' || echo "FAIL info"
echo hi > shared && podman --remote run --rm --network=none --pull=never -v "$PWD:/w" docker.io/library/alpine:latest cat /w/shared 2>&1 | head -3
echo done
`, nil)
	t.Log(out)
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, e.paths.Cache) {
		t.Fatalf("code %d:\n%s", code, out)
	}
}

// TestPodmanThroughProxy pulls a real image, so it needs the network.
func TestPodmanThroughProxy(t *testing.T) {
	if os.Getenv("DORIATH_TEST_NETWORK") == "" {
		t.Skip("set DORIATH_TEST_NETWORK=1 to pull a real image through the proxy")
	}
	if lookPath("podman") == "" || lookPath("unshare") == "" || lookPath("nsenter") == "" {
		t.Skip("podman, unshare or nsenter missing")
	}
	e := newEnv(t)
	t.Cleanup(func() {
		if err := session.RemoveAsMapped(context.Background(), lookPath("unshare"), filepath.Join(e.paths.Cache, "agents")); err != nil {
			t.Log(err)
		}
	})
	e.dialer = &net.Dialer{Timeout: 30 * time.Second}
	e.roots = nil
	e.bundle = "/etc/ssl/certs/ca-certificates.crt"
	body := fmt.Sprintf("modules = [\"podman\"]\n[[mounts]]\npath = %q\nmode = \"write\"\n[egress]\nallow = [\"example.com\"]\n", e.work)
	if err := os.WriteFile(filepath.Join(e.paths.Profiles(), "net.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	l := &profile.Loader{Profiles: os.DirFS(e.paths.Profiles()), Modules: []fs.FS{modules.FS}, Home: e.home}
	p, err := l.Load("net")
	if err != nil {
		t.Fatal(err)
	}
	code, out := e.run(p, `
podman --remote pull -q docker.io/library/alpine:latest >/dev/null || echo "FAIL pull"
echo shared-file > shared
podman --remote run --rm -v "$PWD:/w" docker.io/library/alpine:latest cat /w/shared || echo "FAIL mount"
podman --remote run --rm docker.io/library/alpine:latest wget -qO- https://example.com | grep -q "Example Domain" || echo "FAIL container egress"
podman --remote run --rm docker.io/library/alpine:latest wget -qO- https://example.org >/dev/null 2>&1 && echo "FAIL container reached a denied host"
podman --remote run --rm -v "$HOME/.ssh:/s" docker.io/library/alpine:latest ls /s >/dev/null 2>&1 && echo "FAIL ssh mounted"
podman --remote run --rm --privileged docker.io/library/alpine:latest true 2>&1 | grep -q "doriath:" || echo "FAIL privileged not refused by doriath"
ls "$XDG_RUNTIME_DIR"/../../../run/doriath 2>/dev/null && echo "FAIL session dir visible"
echo done
`, nil)
	t.Log(out)
	if strings.Contains(out, "FAIL") {
		audit, _ := os.ReadFile(e.paths.AuditLog())
		t.Log(string(audit))
	}
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "shared-file") {
		t.Fatalf("code %d", code)
	}
}

func TestStatusInsideJail(t *testing.T) {
	e := newEnv(t)
	code, out := e.run(e.profile(""), `
curl -s https://example.org/ >/dev/null 2>&1
curl -s https://example.org/ >/dev/null 2>&1
/run/doriath-bin/doriath status
/run/doriath-bin/doriath __hook claude session-start </dev/null
`, nil)
	if code != 0 {
		t.Fatalf("code %d:\n%s", code, out)
	}
	for _, want := range []string{`profile "it"`, "example.com", "POST /repos/*/*/releases: approve", "example.org: host not in the profile (2 times)", `"hookEventName":"SessionStart"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	audit, _ := os.ReadFile(e.paths.AuditLog())
	if n := strings.Count(string(audit), `"host":"example.org"`); n != 2 {
		t.Errorf("a repeated denial is logged once, plus once in the summary; got %d lines", n)
	}
}

func TestCredentialOnlyForListedBinaries(t *testing.T) {
	if lookPath("python3") == "" {
		t.Skip("python3 not installed")
	}
	e := newEnv(t)
	e.binaries = `, binaries = ["curl"]`
	code, out := e.run(e.profile(""), `
curl -sS -o /dev/null https://api.github.com/curl
python3 -c 'import urllib.request; urllib.request.urlopen("https://api.github.com/python").read()'
echo done
`, nil)
	if code != 0 || !strings.Contains(out, "done") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if r := e.upstream.find("/curl"); r == nil || r.Header.Get("Authorization") != "Bearer real-token" {
		t.Fatalf("curl must get the credential: %+v", r)
	}
	if r := e.upstream.find("/python"); r == nil || r.Header.Get("Authorization") != "" {
		t.Fatalf("python must reach the host without the credential: %+v", r)
	}
}

func TestHardening(t *testing.T) {
	e := newEnv(t)
	code, out := e.run(e.profile(""), `
unshare -U true 2>/dev/null && echo "FAIL user namespace"
grep -q "doriath.* init" /proc/2/cmdline 2>/dev/null || tr '\0' ' ' < /proc/2/cmdline | grep -q init || echo "FAIL pid 2 is not doriath init"
cat /proc/2/environ >/dev/null 2>&1 && echo "FAIL init's memory and environment are readable"
bwrap --unshare-all --ro-bind / / true 2>/dev/null && echo "FAIL nested bwrap"
touch /mnt/x 2>/dev/null && echo "FAIL write outside the writable paths"
touch "$PWD/landlock-ok" || echo "FAIL worktree write"
python3 -c 'import threading; t=threading.Thread(target=print, args=("threads ok",)); t.start(); t.join()' || echo "FAIL threads"
cat > /tmp/sec.py <<'PY'
import errno, fcntl, socket, termios, os
def refused(f):
    try:
        f()
    except OSError as e:
        return e.errno == errno.EPERM
    return False
print("packet refused" if refused(lambda: socket.socket(socket.AF_PACKET, socket.SOCK_RAW)) else "FAIL packet socket")
print("alg refused" if refused(lambda: socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET)) else "FAIL alg socket")
socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()
socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).close()
print("inet ok")
print("tiocsti refused" if refused(lambda: fcntl.ioctl(0, termios.TIOCSTI, b"x")) else "FAIL tiocsti")
PY
python3 /tmp/sec.py
echo done
`, nil)
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "threads ok") || !strings.Contains(out, "tiocsti refused") || !strings.Contains(out, "inet ok") || !strings.Contains(out, "done") {
		t.Fatalf("code %d:\n%s", code, out)
	}

	p := e.profile("\n[hardening]\nnamespaces = true\nlandlock = false\n")
	code, out = e.run(p, `
bwrap --unshare-all --ro-bind / / true || echo "FAIL nested bwrap with namespaces allowed"
touch /mnt/x || echo "FAIL tmpfs write without landlock"
echo done
`, nil)
	if code != 0 || strings.Contains(out, "FAIL") {
		t.Fatalf("relaxed: code %d:\n%s", code, out)
	}
}

func TestDraftedRuleFromDenial(t *testing.T) {
	e := newEnv(t)
	var req approval.Request
	code, out := e.run(e.profile(""), `
curl -s -o /dev/null https://drafted.example/ && echo "FAIL allowed before approval"
for i in $(seq 1 60); do
	if curl -s -o /dev/null https://drafted.example/after; then echo "allowed after approval"; break; fi
	sleep 0.25
done
`, func() {
		req = e.decideNext(approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession, By: "test"})
	})
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "allowed after approval") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if req.Kind != approval.KindHost || !strings.Contains(req.Summary, "drafted.example") || !strings.Contains(req.Details, "curl") {
		t.Errorf("proposal = %+v", req)
	}
	if req.Keep != "[egress]\nallow = [\"drafted.example\"]" {
		t.Errorf("the proposal must show how to keep the host: %q", req.Keep)
	}
	if entries, _ := os.ReadDir(e.paths.Profiles()); len(entries) != 1 || entries[0].Name() != "it.toml" {
		t.Errorf("doriath must not write profiles: %v", entries)
	}
}

func TestForgedIdentityHeaderIsIgnored(t *testing.T) {
	if lookPath("python3") == "" {
		t.Skip("python3 not installed")
	}
	e := newEnv(t)
	e.binaries = `, binaries = ["curl"]`
	forge := `import os, socket, sys
if os.fork(): os._exit(0)
os.setsid()
if os.fork(): os._exit(0)
s = socket.socket(socket.AF_UNIX)
s.connect("/run/doriath/proxy.sock")
s.sendall(b'DORIATH-PEER {"pid":1,"exe":"/usr/bin/curl"}\nGET https://api.github.com/forged HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n')
print(s.recv(200).decode(errors="replace").splitlines()[0], flush=True)
`
	if err := os.WriteFile(filepath.Join(e.work, "forge.py"), []byte(forge), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := e.run(e.profile(""), "python3 forge.py\nsleep 1\n", nil)
	if code != 0 {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if r := e.upstream.find("/forged"); r != nil && r.Header.Get("Authorization") != "" {
		t.Fatalf("a forged header got the credential")
	}
}

func TestLimitsRunTheSessionInAScope(t *testing.T) {
	systemdRun := lookPath("systemd-run")
	if systemdRun == "" || exec.Command(systemdRun, "--user", "--scope", "--quiet", "true").Run() != nil {
		t.Skip("no systemd user manager")
	}
	e := newEnv(t)
	e.systemdRun = systemdRun
	p := e.profile("\n[limits]\ntasks = 64\n")
	release := filepath.Join(e.work, "release")
	var tasksMax string
	code, out := e.run(p, `while [ ! -e "$PWD/release" ]; do sleep 0.05; done`, func() {
		defer func() { _ = os.WriteFile(release, nil, 0o600) }()
		unit := fmt.Sprintf("doriath-%s-agent-%s.scope", p.Name, e.lastID)
		for range 100 {
			got, _ := exec.Command("systemctl", "--user", "show", "-p", "TasksMax", "--value", unit).Output()
			if tasksMax = strings.TrimSpace(string(got)); tasksMax == "64" {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
	if code != 0 || tasksMax != "64" {
		t.Fatalf("code %d, TasksMax %q:\n%s", code, tasksMax, out)
	}
}

func TestExecJoinsTheRunningJail(t *testing.T) {
	e := newEnv(t)
	release := filepath.Join(e.work, "release")
	var out []byte
	var execErr error
	code, sessionOut := e.run(e.profile(""), `
echo inside > /tmp/marker
while [ ! -e "$PWD/release" ]; do sleep 0.05; done
echo done
`, func() {
		defer func() { _ = os.WriteFile(release, nil, 0o600) }()
		entry := filepath.Join(e.paths.Sessions(), e.lastID, session.EntryFile)
		for range 200 {
			if _, err := os.Stat(entry); err == nil {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		cmd := exec.Command(doriathBin, "exec", "--session", e.lastID, "--", "sh", "-c", `
for i in $(seq 100); do [ -e /tmp/marker ] && break; sleep 0.05; done
cat /tmp/marker
grep -q '^CapEff:[[:space:]]*0*$' /proc/self/status || echo "FAIL capabilities kept"
unshare -U true 2>/dev/null && echo "FAIL user namespace"
touch /mnt/x 2>/dev/null && echo "FAIL write outside the writable paths"
touch "$PWD/from-exec" || echo "FAIL worktree write"
test -n "$HTTPS_PROXY" || echo "FAIL jail environment missing"
`)
		cmd.Dir = e.work
		cmd.Env = []string{"HOME=" + e.home, "XDG_RUNTIME_DIR=" + filepath.Dir(e.paths.Runtime), "PATH=" + os.Getenv("PATH")}
		out, execErr = cmd.CombinedOutput()
	})
	if code != 0 || !strings.Contains(sessionOut, "done") {
		t.Fatalf("session code %d:\n%s", code, sessionOut)
	}
	if execErr != nil || strings.Contains(string(out), "FAIL") || !strings.Contains(string(out), "inside") {
		t.Fatalf("exec: %v\n%s", execErr, out)
	}
	if _, err := os.Stat(filepath.Join(e.work, "from-exec")); err != nil {
		t.Errorf("exec did not write in the session's working directory: %v", err)
	}
}

func TestProgramEgressReachesOnlyNamedPrograms(t *testing.T) {
	e := newEnv(t)
	p := e.profile("\n[[egress.programs]]\nbinaries = [\"curl\"]\nallow = [\"programs.example\"]\n")
	code, out := e.run(p, `
curl -sS -o /dev/null -w "curl %{http_code}\n" https://programs.example/
python3 -c '
import urllib.request
try:
    urllib.request.urlopen("https://programs.example/", timeout=5)
    print("FAIL python reached a curl-only host")
except Exception as e:
    print("python refused:", e)
'
`, nil)
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "curl 200") || !strings.Contains(out, "python refused") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	audit, _ := os.ReadFile(e.paths.AuditLog())
	if !strings.Contains(string(audit), "host allowed only for curl") {
		t.Errorf("the denial does not say which programs may reach the host:\n%s", audit)
	}
}

func TestForwardReachesAPortInsideTheJail(t *testing.T) {
	e := newEnv(t)
	release := filepath.Join(e.work, "release")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hostPort := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	var body string
	code, out := e.run(e.profile(""), `
echo "from inside the jail" > served
python3 -m http.server --bind 127.0.0.1 8765 >/dev/null 2>&1 &
while [ ! -e "$PWD/release" ]; do sleep 0.05; done
echo done
`, func() {
		defer func() { _ = os.WriteFile(release, nil, 0o600) }()
		entry := filepath.Join(e.paths.Sessions(), e.lastID, session.EntryFile)
		for range 200 {
			if _, err := os.Stat(entry); err == nil {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		fwd := exec.Command(doriathBin, "forward", "--session", e.lastID, fmt.Sprintf("%d:8765", hostPort))
		fwd.Env = []string{"HOME=" + e.home, "XDG_RUNTIME_DIR=" + filepath.Dir(e.paths.Runtime), "PATH=" + os.Getenv("PATH")}
		if err := fwd.Start(); err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = fwd.Process.Kill(); _ = fwd.Wait() }()
		for range 100 {
			resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/served", hostPort))
			if err == nil {
				data, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if body = string(data); strings.Contains(body, "inside") {
					return
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
	if code != 0 || !strings.Contains(out, "done") {
		t.Fatalf("session code %d:\n%s", code, out)
	}
	if !strings.Contains(body, "from inside the jail") {
		t.Fatalf("forwarded port served %q", body)
	}
}

func TestALinkToAServerInTheJailForwardsItsPortOnceAllowed(t *testing.T) {
	e := newEnv(t)
	e.hostWait = 30 * time.Second
	release := filepath.Join(e.work, "release")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	served := make(chan string, 1)
	e.open = func(link string) error {
		go func() {
			defer func() { _ = os.WriteFile(release, nil, 0o600) }()
			for range 100 {
				resp, err := http.Get(link)
				if err == nil {
					data, _ := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					served <- string(data)
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
			served <- ""
		}()
		return nil
	}
	code, out := e.run(e.profile(""), fmt.Sprintf(`
G=/run/doriath-bin/doriath
echo "from inside the jail" > served
python3 -m http.server --bind 127.0.0.1 %[1]d >/dev/null 2>&1 &
sleep 0.5
$G request open http://localhost:%[1]d/served --reason "preview the docs" || echo "FAIL request open"
$G request forward %[1]d || echo "FAIL the allowed forward asked again"
$G status | grep -q "Port %[1]d in the jail is forwarded" || echo "FAIL status does not list the forward"
while [ ! -e "$PWD/release" ]; do sleep 0.05; done
echo done
`, port), func() {
		allow := approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession, By: "test"}
		if req := e.decideNext(allow); req.Kind != approval.KindForward || req.Note != "preview the docs" {
			t.Errorf("forward request: %+v", req)
		}
	})
	if code != 0 || !strings.Contains(out, "done") || strings.Contains(out, "FAIL") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if body := <-served; !strings.Contains(body, "from inside the jail") {
		t.Fatalf("the forwarded link served %q", body)
	}
	if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err != nil {
		t.Errorf("the forward outlived the session: %v", err)
	} else {
		_ = l.Close()
	}
}

func TestAConnectReachesAPortOfTheHostOnceAllowed(t *testing.T) {
	e := newEnv(t)
	e.hostWait = 30 * time.Second
	host, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	hostPort := host.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := host.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("from the host\n"))
			_ = c.Close()
		}
	}()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	jailPort := free.Addr().(*net.TCPAddr).Port
	_ = free.Close()
	code, out := e.run(e.profile(""), fmt.Sprintf(`
G=/run/doriath-bin/doriath
(exec 3<>/dev/tcp/127.0.0.1/%[2]d) 2>/dev/null && echo "FAIL the port was open before the request"
$G request connect %[1]d:%[2]d --reason "query the staging database" || echo "FAIL request connect"
$G request connect %[1]d:%[2]d || echo "FAIL the allowed connect asked again"
exec 4<>/dev/tcp/127.0.0.1/%[2]d || echo "FAIL the jail cannot connect"
read -r line <&4
echo "got: $line"
$G status | grep -q "127.0.0.1:%[2]d in the jail reaches port %[1]d" || echo "FAIL status does not list the connect"
echo done
`, hostPort, jailPort), func() {
		allow := approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession, By: "test"}
		if req := e.decideNext(allow); req.Kind != approval.KindConnect || req.Note != "query the staging database" || req.Scope != fmt.Sprintf("connect %d:%d", hostPort, jailPort) {
			t.Errorf("connect request: %+v", req)
		}
	})
	if code != 0 || !strings.Contains(out, "got: from the host") || !strings.Contains(out, "done") || strings.Contains(out, "FAIL") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}

func TestAnOptionalSecretThatCannotBeReadLeavesTheSessionRunning(t *testing.T) {
	e := newEnv(t)
	e.secrets["github"] = secret.Backend{File: filepath.Join(e.work, "missing-token")}
	code, out := e.run(e.profile(""), `curl -sS https://api.github.com/user`, nil)
	if code != 0 || !strings.Contains(out, `secret \"github\": stat `) || !strings.Contains(out, "doriath asked the user to fix it on the approvals page") || !strings.Contains(out, "secrets missing github") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}

func TestARequiredSecretThatCannotBeReadStopsTheSessionBeforeTheAgent(t *testing.T) {
	e := newEnv(t)
	e.secrets["github"] = secret.Backend{File: filepath.Join(e.work, "missing-token"), Required: true}
	_, out, err := e.start(e.profile(""), `echo ran > "$PWD/ran"`, nil)
	if err == nil || !strings.Contains(err.Error(), `secret "github"`) {
		t.Fatalf("err = %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(e.work, "ran")); err == nil {
		t.Error("the agent ran without its secret")
	}
}

func TestARefusedHostIsRefusedWithoutAsking(t *testing.T) {
	e := newEnv(t)
	p := e.profile("")
	p.Egress.Deny = []profile.HostPattern{"example.org"}
	code, out := e.run(p, `curl -sS -o /dev/null https://example.org 2>&1; echo; echo done`, nil)
	if code != 0 || !strings.Contains(out, "example.org ×1") || strings.Contains(out, "pending") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}

func TestASessionStartsInAReadOnlyCheckoutWhoseHookConfigIsASymlink(t *testing.T) {
	e := newEnv(t)
	e.modules = []string{"vcs-readonly"}
	repo := filepath.Join(e.home, "checkout")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "init", "-q", "-b", "main")
	target := filepath.Join(e.home, "pre-commit-config.json")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(repo, ".pre-commit-config.yaml")); err != nil {
		t.Fatal(err)
	}
	e.cwd = repo
	code, out := e.run(e.profile(fmt.Sprintf("[[mounts]]\npath = %q\n", repo)), `echo started`, nil)
	if code != 0 || !strings.Contains(out, "started") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}

func TestTheJailCannotRepointAGuardedLinkInAWritableCheckout(t *testing.T) {
	for name, guarded := range map[string]string{
		"a hook config that git-hooks.nix links": ".pre-commit-config.yaml",
		"a jj config that jj moved out":          ".jj/repo/config.toml",
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.modules = []string{"vcs-readwrite"}
			git(t, e.work, "init", "-q", "-b", "main")
			target := filepath.Join(e.home, "outside", "config")
			link := filepath.Join(e.work, guarded)
			for _, d := range []string{filepath.Dir(target), filepath.Dir(link)} {
				if err := os.MkdirAll(d, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			script := fmt.Sprintf(`ln -sfn /tmp/planted %q; for i in $(seq 50); do [ "$(readlink %q)" = %q ] && break; sleep 0.1; done; echo "during: $(readlink %q)"`, link, link, target, link)
			code, out := e.run(e.profile(""), script, nil)
			if code != 0 || !strings.Contains(out, "during: "+target) || !strings.Contains(out, "put the link back") {
				t.Fatalf("code %d:\n%s", code, out)
			}
			if got, err := os.Readlink(link); err != nil || got != target {
				t.Errorf("after the session the link is %q, %v", got, err)
			}
		})
	}
}

func TestASignInLinkOpensOnTheHostAndItsRedirectReachesTheJail(t *testing.T) {
	e := newEnv(t)
	const port = 18765
	opened := make(chan string, 1)
	e.open = func(link string) error {
		opened <- link
		go func() {
			for range 50 {
				resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/callback?code=from-the-browser", port))
				if err == nil {
					_ = resp.Body.Close()
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()
		return nil
	}
	got := filepath.Join(e.work, "callback")
	rule := "\n[[open]]\nhost = \"login.example\"\npath = \"/oauth/authorize\"\naction = \"allow\"\nforward_redirect = true\n"
	code, out := e.run(e.profile(rule), fmt.Sprintf(`
/usr/bin/python3 -c '
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        open(sys.argv[1], "w").write(self.path)
        self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", %[1]d), H).handle_request()
' %[2]s &
sleep 0.5
xdg-open "https://login.example/oauth/authorize?client_id=x&redirect_uri=http://localhost:%[1]d/callback" || echo "FAIL xdg-open"
"$BROWSER" "file:///etc/passwd" 2>/dev/null && echo "FAIL a file link opened"
wait
cat %[2]s
`, port, got), nil)
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "/callback?code=from-the-browser") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	select {
	case link := <-opened:
		if !strings.HasPrefix(link, "https://login.example/oauth/authorize?") {
			t.Errorf("opened %q", link)
		}
	default:
		t.Error("the link never reached the host")
	}
}
