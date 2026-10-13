//go:build integration

package containers

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/fnune/girdle/internal/approval"
)

// tool is a static binary for a test image, so that the tests need no
// registry.
const toolSource = `package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func main() {
	switch os.Args[1] {
	case "echo":
		fmt.Println(strings.Join(os.Args[2:], " "))
	case "cat":
		data, err := os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Stdout.Write(data)
	case "stdin":
		io.Copy(os.Stdout, os.Stdin)
	case "ticks":
		for i := 1; i <= 3; i++ {
			fmt.Printf("tick %d\n", i)
			time.Sleep(300 * time.Millisecond)
		}
	case "sleep":
		time.Sleep(time.Minute)
	}
}
`

type osPaths struct{}

func (osPaths) EvalSymlinks(p string) (string, error) { return filepath.EvalSymlinks(p) }

type podmanEnv struct {
	t      *testing.T
	env    []string
	root   string
	run    string
	sock   string
	broker string
}

// on returns the environment for a subtest, so that failures end the
// subtest.
func (p *podmanEnv) on(t *testing.T) *podmanEnv {
	q := *p
	q.t = t
	return &q
}

func (p *podmanEnv) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "podman", args...)
	cmd.Env = p.env
	return cmd
}

// remote runs the podman client against the broker.
func (p *podmanEnv) remote(stdin string, args ...string) (string, string, error) {
	p.t.Helper()
	ctx, cancel := context.WithTimeout(p.t.Context(), 2*time.Minute)
	defer cancel()
	cmd := p.command(ctx, append([]string{"--remote", "--url", "unix://" + p.broker}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func (p *podmanEnv) mustRemote(stdin string, args ...string) string {
	p.t.Helper()
	out, errOut, err := p.remote(stdin, args...)
	if err != nil {
		p.t.Fatalf("podman %s: %v\n%s%s", strings.Join(args, " "), err, out, errOut)
	}
	return out
}

func (p *podmanEnv) refused(want string, args ...string) {
	p.t.Helper()
	out, errOut, err := p.remote("", args...)
	if err == nil {
		p.t.Fatalf("podman %s succeeded: %s", strings.Join(args, " "), out)
	}
	if !strings.Contains(errOut, want) {
		p.t.Fatalf("podman %s: stderr %q lacks %q", strings.Join(args, " "), errOut, want)
	}
}

// mustContainer creates a container and returns its ID.
func (p *podmanEnv) mustContainer(image string) string {
	p.t.Helper()
	id := strings.TrimSpace(p.mustRemote("", "create", image, "true"))
	p.t.Cleanup(func() { _, _, _ = p.remote("", "rm", "-f", id) })
	return id
}

func writeFiles(t *testing.T, files map[string]string) {
	t.Helper()
	for p, content := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// startPodman runs a podman service with its own storage, configuration and
// runtime directory, so that the user's containers are never touched.
func startPodman(t *testing.T) *podmanEnv {
	t.Helper()
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman is not on PATH")
	}
	tmp := t.TempDir()
	p := &podmanEnv{t: t, root: filepath.Join(tmp, "storage"), run: filepath.Join(tmp, "run", "storage"), broker: filepath.Join(tmp, "broker.sock")}
	home := filepath.Join(tmp, "home")
	conf := filepath.Join(tmp, "conf")
	writeFiles(t, map[string]string{
		filepath.Join(conf, "storage.conf"):                         "[storage]\ndriver = \"vfs\"\ngraphroot = \"" + p.root + "\"\nrunroot = \"" + p.run + "\"\n",
		filepath.Join(conf, "containers.conf"):                      "[containers]\nnetns = \"host\"\ncgroups = \"disabled\"\nlog_driver = \"k8s-file\"\n[engine]\ncgroup_manager = \"cgroupfs\"\nevents_logger = \"file\"\n",
		filepath.Join(conf, "registries.conf"):                      "unqualified-search-registries = [\"docker.io\"]\nshort-name-mode = \"permissive\"\n",
		filepath.Join(home, ".config", "containers", "policy.json"): `{"default": [{"type": "insecureAcceptAnything"}]}`,
	})
	runtimeDir := filepath.Join(tmp, "run")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	p.env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_RUNTIME_DIR=" + runtimeDir,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"XDG_DATA_HOME=" + filepath.Join(home, ".local", "share"),
		"CONTAINERS_CONF=" + filepath.Join(conf, "containers.conf"),
		"CONTAINERS_STORAGE_CONF=" + filepath.Join(conf, "storage.conf"),
		"CONTAINERS_REGISTRIES_CONF=" + filepath.Join(conf, "registries.conf"),
	}
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"} {
		if v, ok := os.LookupEnv(k); ok {
			p.env = append(p.env, k+"="+v)
		}
	}

	sock := filepath.Join(tmp, "podman.sock")
	svc := exec.Command("podman", "--root", p.root, "--runroot", p.run, "system", "service", "--time=0", "unix://"+sock)
	svc.Env = p.env
	var logs bytes.Buffer
	svc.Stdout, svc.Stderr = &logs, &logs
	svc.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := svc.Start(); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- svc.Wait() }()
	t.Cleanup(func() {
		_ = syscall.Kill(-svc.Process.Pid, syscall.SIGTERM)
		select {
		case <-waited:
		case <-time.After(10 * time.Second):
			_ = syscall.Kill(-svc.Process.Pid, syscall.SIGKILL)
			<-waited
		}
		// Container storage holds files owned by subordinate ids, which only
		// the user namespace can remove.
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		rm := p.command(ctx, "--root", p.root, "--runroot", p.run, "unshare", "rm", "-rf", p.root, p.run)
		if out, err := rm.CombinedOutput(); err != nil {
			t.Logf("remove storage: %v: %s", err, out)
		}
		if t.Failed() {
			t.Logf("podman service log:\n%s", logs.String())
		}
	})
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		select {
		case err := <-waited:
			t.Fatalf("podman service exited: %v\n%s", err, logs.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("podman socket did not appear\n%s", logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	p.sock = sock
	return p
}

func (p *podmanEnv) startBroker(policy Policy, pins Pins) *events {
	p.t.Helper()
	rec := &events{}
	b := New(policy, p.sock, &fakeApprover{verdict: approval.VerdictDeny}, rec, Config{Session: "it", Profile: "dev", ApprovalTTL: time.Second, Resolver: osPaths{}, Pins: pins})
	l, err := net.Listen("unix", p.broker)
	if err != nil {
		p.t.Fatal(err)
	}
	p.t.Cleanup(func() { _ = l.Close() })
	go func() { _ = b.Serve(l) }()
	return rec
}

// testImage imports a one-file image built from toolSource.
func (p *podmanEnv) testImage(name string) {
	p.t.Helper()
	dir := p.t.TempDir()
	src := filepath.Join(dir, "main.go")
	writeFiles(p.t, map[string]string{src: toolSource})
	bin := filepath.Join(dir, "tool")
	build := exec.CommandContext(p.t.Context(), "go", "build", "-o", bin, src)
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GO111MODULE=off")
	if out, err := build.CombinedOutput(); err != nil {
		p.t.Fatalf("build tool: %v: %s", err, out)
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		p.t.Fatal(err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "tool", Mode: 0o755, Size: int64(len(data))}); err != nil {
		p.t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		p.t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		p.t.Fatal(err)
	}
	archive := filepath.Join(dir, "image.tar")
	if err := os.WriteFile(archive, buf.Bytes(), 0o600); err != nil {
		p.t.Fatal(err)
	}
	p.mustRemote("", "import", archive, name)
}

func TestPodmanThroughBroker(t *testing.T) {
	p := startPodman(t)
	allowed := t.TempDir()
	writeFiles(t, map[string]string{filepath.Join(allowed, "file"): "from the worktree\n"})
	outside := t.TempDir()
	pins := &memPins{pins: map[string]string{}}
	rec := p.startBroker(Policy{
		Images: []string{"docker.io/library/*", "localhost/*"},
		Mounts: []Mount{{Path: allowed}},
	}, pins)

	if out := p.mustRemote("", "info", "--format", "{{.Store.GraphRoot}}"); strings.TrimSpace(out) != p.root {
		t.Fatalf("info reports graph root %q, want %q", out, p.root)
	}
	const img = "localhost/girdle-test"
	p.testImage(img)

	t.Run("privileged refused", func(t *testing.T) {
		p := p.on(t)
		p.refused("girdle: privileged containers are not allowed", "run", "--rm", "--privileged", img, "/tool", "echo", "x")
	})
	t.Run("bind outside refused", func(t *testing.T) {
		p := p.on(t)
		p.refused("outside the mounts and caches", "run", "--rm", "-v", outside+":/s", img, "/tool", "echo", "x")
	})
	t.Run("pull of another registry refused", func(t *testing.T) {
		p := p.on(t)
		p.refused("[podman] images", "pull", "quay.io/podman/hello")
	})
	t.Run("play kube refused", func(t *testing.T) {
		p := p.on(t)
		kube := filepath.Join(t.TempDir(), "pod.yaml")
		writeFiles(t, map[string]string{kube: "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n"})
		p.refused("kube YAML", "kube", "play", kube)
	})
	t.Run("attach output", func(t *testing.T) {
		p := p.on(t)
		out := p.mustRemote("", "run", "--rm", "-v", allowed+":/w:ro", img, "/tool", "cat", "/w/file")
		if out != "from the worktree\n" {
			t.Fatalf("output %q", out)
		}
	})
	t.Run("attach stdin", func(t *testing.T) {
		p := p.on(t)
		out := p.mustRemote("through stdin\n", "run", "--rm", "-i", img, "/tool", "stdin")
		if out != "through stdin\n" {
			t.Fatalf("output %q", out)
		}
	})
	t.Run("logs follow", func(t *testing.T) {
		p := p.on(t)
		p.mustRemote("", "run", "-d", "--name", "ticker", img, "/tool", "ticks")
		out := p.mustRemote("", "logs", "-f", "ticker")
		if out != "tick 1\ntick 2\ntick 3\n" {
			t.Fatalf("logs %q", out)
		}
	})
	t.Run("exec", func(t *testing.T) {
		p := p.on(t)
		p.mustRemote("", "run", "-d", "--name", "sleeper", img, "/tool", "sleep")
		if out := p.mustRemote("", "exec", "sleeper", "/tool", "echo", "from exec"); out != "from exec\n" {
			t.Fatalf("exec output %q", out)
		}
		if out := p.mustRemote("piped\n", "exec", "-i", "sleeper", "/tool", "stdin"); out != "piped\n" {
			t.Fatalf("exec stdin output %q", out)
		}
		p.refused("girdle: privileged exec sessions are not allowed", "exec", "--privileged", "sleeper", "/tool", "echo", "x")
		p.mustRemote("", "rm", "-f", "-t", "0", "sleeper")
	})
	t.Run("build", func(t *testing.T) {
		p := p.on(t)
		ctxDir := t.TempDir()
		writeFiles(t, map[string]string{filepath.Join(ctxDir, "Containerfile"): "FROM " + img + "\nRUN [\"/tool\", \"echo\", \"built in a step\"]\n"})
		out := p.mustRemote("", "build", "-t", "localhost/girdle-built", ctxDir)
		if !strings.Contains(out, "built in a step") {
			t.Fatalf("build output %q", out)
		}
		p.refused("girdle: builds with addcaps", "build", "--cap-add", "SYS_ADMIN", ctxDir)
	})
	t.Run("push asks and is denied", func(t *testing.T) {
		p := p.on(t)
		p.refused("Push container image", "push", img, "docker.io/acme/x:1")
	})

	if !slices.Contains(rec.kinds(), "denied") {
		t.Error("no refusal was recorded")
	}
	if os.Getenv("GIRDLE_TEST_NETWORK") != "1" {
		t.Log("set GIRDLE_TEST_NETWORK=1 to pull alpine")
		return
	}
	t.Run("alpine", func(t *testing.T) {
		p := p.on(t)
		out := p.mustRemote("", "run", "--rm", "-v", allowed+":/w", "alpine", "cat", "/w/file")
		if out != "from the worktree\n" {
			t.Fatalf("output %q", out)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		p.refused("outside the mounts and caches", "run", "--rm", "-v", filepath.Join(home, ".ssh")+":/s", "alpine", "true")
	})
	t.Run("pins", func(t *testing.T) {
		p := p.on(t)
		pinned, ok, _ := pins.Pinned("docker.io/library/alpine:latest")
		if !ok {
			t.Fatal("alpine was not pinned")
		}
		out := p.mustRemote("", "inspect", "--format", "{{.ImageName}}", p.mustContainer("alpine"))
		if strings.TrimSpace(out) != "docker.io/library/alpine@"+pinned {
			t.Fatalf("container runs %q, want the pinned digest %s", out, pinned)
		}
		if err := pins.Pin("docker.io/library/alpine:latest", "sha256:"+strings.Repeat("0", 64)); err != nil {
			t.Fatal(err)
		}
		p.refused("changed from sha256:000000000000", "pull", "alpine")
		client := &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", p.broker)
			},
		}}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://d/v1.41/images/create?fromImage=alpine&tag=latest", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), `"errorDetail":{"message":"girdle: docker.io/library/alpine:latest changed from sha256:000000000000`) {
			t.Fatalf("Docker pull stream %s", body)
		}
	})
}
