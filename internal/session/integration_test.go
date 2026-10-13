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
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/fnune/girdle/internal/approval"
	"github.com/fnune/girdle/internal/bundle"
	"github.com/fnune/girdle/internal/ca"
	"github.com/fnune/girdle/internal/config"
	"github.com/fnune/girdle/internal/control"
	"github.com/fnune/girdle/internal/modules"
	"github.com/fnune/girdle/internal/notify"
	"github.com/fnune/girdle/internal/profile"
	"github.com/fnune/girdle/internal/secret"
	"github.com/fnune/girdle/internal/session"
)

var girdleBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "girdle-it-")
	if err != nil {
		panic(err)
	}
	girdleBin = filepath.Join(dir, "girdle")
	out, err := exec.Command("go", "build", "-o", girdleBin, "github.com/fnune/girdle/cmd/girdle").CombinedOutput()
	if err != nil {
		panic(string(out))
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

type recorder struct {
	mu   sync.Mutex
	reqs []*http.Request
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	_, _ = io.Copy(io.Discard, req.Body)
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	r.mu.Unlock()
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
	t        *testing.T
	home     string
	work     string
	paths    config.Paths
	upstream *recorder
	dialer   proxyDialer
	bundle   string
	secrets  map[string]secret.Backend
	roots    *ca.Authority
	// binaries is spliced into the api.github.com credential.
	binaries string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	if _, err := exec.LookPath("bwrap"); err != nil && !bundle.Bundled() {
		t.Skip("bubblewrap not available")
	}
	// Unix socket paths are limited to 108 bytes, and test names are long.
	root, err := os.MkdirTemp("/tmp", "gi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
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

	upCA, err := ca.New([]string{"example.com", "api.github.com", "github.com", "drafted.example"}, time.Now)
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
			Runtime: filepath.Join(root, "run"),
		},
		upstream: up,
		dialer:   redirect{addr: srv.Listener.Addr().String()},
		bundle:   bundlePath,
		roots:    upCA,
		secrets:  map[string]secret.Backend{"gh": {File: tokenPath}},
	}
}

func (e *env) profile(extra string) *profile.Profile {
	e.t.Helper()
	body := fmt.Sprintf(`
modules = ["base"]
secrets = { github = "gh" }

[[mounts]]
path = %q
mode = "rw"

[egress]
allow = ["example.com"]

[[http]]
host = "api.github.com"
credential = { secret = "github", scheme = "bearer"%s }

[[http.rules]]
method = "POST"
path = "/repos/*/*/releases"
action = "approve"
summary = "Create a GitHub release"
%s`, e.work, e.binaries, extra)
	if err := os.WriteFile(filepath.Join(e.paths.Profiles(), "it.toml"), []byte(body), 0o600); err != nil {
		e.t.Fatal(err)
	}
	l := &profile.Loader{Profiles: os.DirFS(e.paths.Profiles()), Modules: []fs.FS{modules.FS}, Home: e.home}
	p, err := l.Load("it")
	if err != nil {
		e.t.Fatal(err)
	}
	return p
}

// run starts a session with script as the command. while runs alongside it,
// for example to decide approvals.
func (e *env) run(p *profile.Profile, script string, while func()) (int, string) {
	e.t.Helper()
	scriptPath := filepath.Join(e.work, "script.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\n"+script), 0o700); err != nil {
		e.t.Fatal(err)
	}
	bwrap, err := bundle.Bwrap(e.paths.Bundle(), os.Getenv)
	if err != nil {
		e.t.Fatal(err)
	}
	var out bytes.Buffer
	getenv := func(k string) string {
		if k == "SSL_CERT_FILE" {
			return e.bundle
		}
		return ""
	}
	deps := session.Deps{
		Paths:         e.paths,
		Secrets:       secret.NewConfigured(e.secrets, nil, secret.OSFiles{}),
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
		Exe:           girdleBin,
		Unshare:       lookPath("unshare"),
		Nsenter:       lookPath("nsenter"),
		Podman:        lookPath("podman"),
		Git:           lookPath("git"),
	}
	s, err := session.New(deps, session.Request{Profile: p, Cwd: e.work, Command: []string{scriptPath}})
	if err != nil {
		e.t.Fatal(err)
	}
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
	if err != nil {
		e.t.Fatalf("session: %v\n%s", err, out.String())
	}
	return code, out.String()
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

// decideNext waits for one pending request and decides it.
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
test -n "$SSH_AUTH_SOCK" && echo "FAIL ssh agent leaked"
test -n "$DBUS_SESSION_BUS_ADDRESS" && echo "FAIL session bus"
ls /run/girdle/token* 2>/dev/null && echo "FAIL token file"
grep -r real-token /run/girdle 2>/dev/null && echo "FAIL token in girdle dir"
echo x > /run/girdle/probe 2>/dev/null && echo "FAIL girdle dir writable"
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

func TestEgressAndInjection(t *testing.T) {
	e := newEnv(t)
	code, out := e.run(e.profile(""), `
curl -sS -o /dev/null -w "tunnel %{http_code}\n" https://example.com/t
curl -sS -o /dev/null -w "denied %{http_code}\n" https://example.org/ 2>/dev/null || true
curl -sS -H "Authorization: token $GH_TOKEN" -o /dev/null -w "api %{http_code}\n" https://api.github.com/user
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
	req := e.upstream.find("/user")
	if req == nil || req.Header.Get("Authorization") != "Bearer real-token" {
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
curl -sS -X POST -d '{}' https://api.github.com/repos/fnune/project/releases
echo
curl -sS -X POST -d '{}' https://api.github.com/repos/fnune/project/releases
echo
curl -sS -X POST -d '{}' https://api.github.com/repos/fnune/project/releases
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
		if strings.TrimSpace(l) != "" && !strings.HasPrefix(l, "girdle: session") {
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
	script := `printf '%s' '{"tool_name":"Bash","tool_input":{"command":"gh release create v1","description":"Create release"}}' | /run/girdle-bin/girdle hook claude permission-request --timeout 30s`
	var req approval.Request
	code, out := e.run(e.profile(""), script, func() {
		req = e.decideNext(approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingOnce, By: "test"})
	})
	if code != 0 || !strings.Contains(out, `"behavior":"allow"`) {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if req.Summary != "Run: Create release" || req.Details != "gh release create v1" || req.Agent != "claude" {
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
printf x > msg; ssh-keygen -Y sign -n file -f /run/girdle/signing.pub msg >/dev/null 2>&1 && echo "FAIL signed outside git namespace"
ssh-add -L | grep -q girdle || echo "FAIL agent key missing"
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
	if os.Getenv("GIRDLE_TEST_NETWORK") == "" {
		t.Skip("set GIRDLE_TEST_NETWORK=1 to pull a real image through the proxy")
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
	body := fmt.Sprintf("modules = [\"base\", \"podman\"]\n[[mounts]]\npath = %q\nmode = \"rw\"\n[egress]\nallow = [\"example.com\"]\n", e.work)
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
/run/girdle-bin/girdle status
/run/girdle-bin/girdle statusline
/run/girdle-bin/girdle hook claude session-start </dev/null
`, nil)
	if code != 0 {
		t.Fatalf("code %d:\n%s", code, out)
	}
	for _, want := range []string{`profile "it"`, "example.com", "POST /repos/*/*/releases: approve", "example.org: host not in the profile (2 times)", "girdle it · 2 hosts · 1 waiting for you · 1 blocked", `"hookEventName":"SessionStart"`} {
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
bwrap --unshare-all --ro-bind / / true 2>/dev/null && echo "FAIL nested bwrap"
touch /mnt/x 2>/dev/null && echo "FAIL write outside the writable paths"
touch "$PWD/landlock-ok" || echo "FAIL worktree write"
python3 -c 'import threading; t=threading.Thread(target=print, args=("threads ok",)); t.start(); t.join()' || echo "FAIL threads"
echo done
`, nil)
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "threads ok") || !strings.Contains(out, "done") {
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
		req = e.decideNext(approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingProfile, By: "test"})
	})
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "allowed after approval") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if req.Kind != approval.KindRule || !strings.Contains(req.Summary, "drafted.example") || !strings.Contains(req.Details, "curl") {
		t.Errorf("proposal = %+v", req)
	}
	local, err := os.ReadFile(filepath.Join(e.paths.Profiles(), "it.local.toml"))
	if err != nil || !strings.Contains(string(local), "drafted.example") {
		t.Fatalf("local layer: %s, %v", local, err)
	}
}

func TestCloneMode(t *testing.T) {
	if lookPath("git") == "" {
		t.Skip("git not installed")
	}
	e := newEnv(t)
	repo := filepath.Join(e.home, "repo")
	gitIn := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.org", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.org")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	gitIn("init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "README"), []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitIn("add", "README")
	gitIn("commit", "-q", "-m", "first")
	base := gitIn("rev-parse", "HEAD")

	p := e.profile(fmt.Sprintf("\n[[mounts]]\npath = %q\nmode = \"clone\"\n", repo))
	code, out := e.run(p, fmt.Sprintf(`
cd %q
test "$(cat README)" = original || echo "FAIL clone content"
git switch -q -c feature
echo agent > README
git -c user.name=Agent -c user.email=a@example.org commit -q -am "agent change" || echo "FAIL commit"
echo x >> .git/config 2>/dev/null && echo "FAIL clone config writable"
echo done
`, repo), nil)
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "done") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	if got, _ := os.ReadFile(filepath.Join(repo, "README")); string(got) != "original\n" {
		t.Fatalf("the source checkout changed: %q", got)
	}
	if head := gitIn("rev-parse", "HEAD"); head != base {
		t.Fatal("the source HEAD moved")
	}
	refs := gitIn("for-each-ref", "--format=%(refname)", "refs/girdle/")
	if !strings.Contains(refs, "/feature") {
		t.Fatalf("no landed branch: %q\noutput:\n%s", refs, out)
	}
	if !strings.Contains(out, "feature has 1 new commit(s)") {
		t.Errorf("no landing summary in:\n%s", out)
	}
	if msg := gitIn("log", "-1", "--format=%s", strings.Fields(refs)[0]); msg != "agent change" && !strings.Contains(refs, "HEAD") {
		t.Errorf("landed commit = %q", msg)
	}
}
