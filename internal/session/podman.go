package session

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fnune/girdle/internal/containers"
	"github.com/fnune/girdle/internal/imagepins"
	"github.com/fnune/girdle/internal/jail"
	"github.com/fnune/girdle/internal/profile"
)

// IDRange is one entry of /etc/subuid or /etc/subgid.
type IDRange struct {
	Start int
	Count int
}

// SubIDs finds the first range for the user, by name or by numeric id.
func SubIDs(data []byte, name string, uid int) (IDRange, error) {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		parts := strings.Split(strings.TrimSpace(sc.Text()), ":")
		if len(parts) != 3 || (parts[0] != name && parts[0] != strconv.Itoa(uid)) {
			continue
		}
		start, err1 := strconv.Atoi(parts[1])
		count, err2 := strconv.Atoi(parts[2])
		if err1 != nil || err2 != nil || count < 1 {
			continue
		}
		return IDRange{Start: start, Count: count}, nil
	}
	return IDRange{}, fmt.Errorf("no subordinate id range for %s: add one with usermod --add-subuids and --add-subgids", name)
}

func ContainersConf(tmpDir, proxyURL string) []byte {
	return []byte(fmt.Sprintf(`# Written by girdle for one session.
[containers]
# Containers share the session's network namespace: they reach the internet
# only through the proxy, and the agent reaches their ports on localhost.
netns = "host"
cgroups = "disabled"
http_proxy = true
# Some tools, such as busybox wget, only read the lowercase variables.
env = ["http_proxy=%[2]s", "https_proxy=%[2]s", "no_proxy=localhost,127.0.0.1,::1"]

[engine]
cgroup_manager = "cgroupfs"
events_logger = "file"
image_copy_tmp_dir = %[1]s
`, quote(tmpDir), proxyURL))
}

const policyJSON = `{"default": [{"type": "insecureAcceptAnything"}]}
`

const registriesConf = `unqualified-search-registries = ["docker.io"]
short-name-mode = "permissive"
`

func StorageConf(graphRoot string) []byte {
	return []byte(fmt.Sprintf(`# Written by girdle for one session.
[storage]
driver = "overlay"
graphroot = %s
runroot = "/run/containers/storage"
`, quote(graphRoot)))
}

const containerProxyPort = 3129

type bwrapInfo struct {
	ChildPID int `json:"child-pid"`
}

func (s *Session) startPodman() error {
	if s.deps.Unshare == "" || s.deps.Podman == "" {
		return errors.New("the podman module needs util-linux unshare and podman on PATH")
	}
	podmanBin, err := filepath.EvalSymlinks(s.deps.Podman)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", s.deps.Podman, err)
	}
	u, err := user.Current()
	if err != nil {
		return err
	}
	uid := os.Getuid()
	subuid, err := readSubIDs("/etc/subuid", u.Username, uid)
	if err != nil {
		return err
	}
	subgid, err := readSubIDs("/etc/subgid", u.Username, uid)
	if err != nil {
		return err
	}

	root := filepath.Join(s.cacheRoot(), "containers")
	for _, d := range []string{filepath.Join(root, "storage"), filepath.Join(root, "tmp")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", d, err)
		}
	}
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", containerProxyPort)
	if err := writeFile(s.jailPath("containers.conf"), ContainersConf(filepath.Join(root, "tmp"), proxyURL), 0o644); err != nil {
		return err
	}
	if err := writeFile(s.jailPath("storage.conf"), StorageConf(filepath.Join(root, "storage")), 0o644); err != nil {
		return err
	}
	if err := writeFile(s.jailPath("policy.json"), []byte(policyJSON), 0o644); err != nil {
		return err
	}
	if err := writeFile(s.jailPath("registries.conf"), []byte(registriesConf), 0o644); err != nil {
		return err
	}
	userConf := filepath.Join(s.deps.Paths.Home, ".config", "containers")

	p := s.req.Profile
	argv := []string{jail.ExePath, "init", "--forward", fmt.Sprintf("%d=%s", containerProxyPort, jail.InJail(ProxySocket))}
	rawDir := filepath.Join(s.dir, "podman")
	if err := os.MkdirAll(rawDir, 0o700); err != nil {
		return err
	}
	raw := filepath.Join(rawDir, "podman.sock")
	argv = append(argv, "--", podmanBin, "system", "service", "--time=0", "unix://"+raw)
	spec, err := jail.Plan(p, s.layout(), jail.Options{
		UID:     0,
		Home:    s.deps.Paths.Home,
		Cwd:     s.req.Cwd,
		Command: argv,
		HostEnv: envMap(s.deps.Environ),
		ExtraEnv: map[string]string{
			"HTTP_PROXY":                 proxyURL,
			"HTTPS_PROXY":                proxyURL,
			"NO_PROXY":                   "localhost,127.0.0.1,::1",
			"SSL_CERT_FILE":              jail.InJail("ca-bundle.pem"),
			"CONTAINERS_CONF":            jail.InJail("containers.conf"),
			"CONTAINERS_STORAGE_CONF":    jail.InJail("storage.conf"),
			"CONTAINERS_REGISTRIES_CONF": jail.InJail("registries.conf"),
		},
		ExtraBinds: []jail.Bind{
			{Source: root, Dest: root},
			{Source: rawDir, Dest: rawDir},
			{Source: s.jailPath("policy.json"), Dest: filepath.Join(userConf, "policy.json"), ReadOnly: true},
		},
		SkipUserNS: true,
		InfoFD:     3,
	}, osHost{})
	if err != nil {
		return fmt.Errorf("plan podman service: %w", err)
	}
	unshareArgs := []string{
		"--user", "--map-root-user",
		fmt.Sprintf("--map-users=1:%d:%d", subuid.Start, min(subuid.Count, 65536)),
		fmt.Sprintf("--map-groups=1:%d:%d", subgid.Start, min(subgid.Count, 65536)),
		"--", s.deps.Bwrap,
	}
	infoR, infoW, err := os.Pipe()
	if err != nil {
		return err
	}
	logPath := filepath.Join(s.cacheRoot(), "podman.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	cmd := s.limited(exec.Command(s.deps.Unshare, append(unshareArgs, spec.Args()...)...), "podman")
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.ExtraFiles = []*os.File{infoW}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = infoW.Close()
		_ = infoR.Close()
		_ = logFile.Close()
		return fmt.Errorf("start podman service: %w", err)
	}
	_ = infoW.Close()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	s.closers = append(s.closers, func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-waited:
		case <-time.After(5 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-waited
		}
		_ = logFile.Close()
	})

	info, err := readInfo(infoR, 10*time.Second)
	_ = infoR.Close()
	if err != nil {
		return fmt.Errorf("podman service did not start: %w (see %s)", err, logPath)
	}
	s.netnsPID = info.ChildPID

	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(raw); err == nil {
			break
		}
		select {
		case err := <-waited:
			waited <- err
			return fmt.Errorf("podman service exited: %w (see %s)", err, logPath)
		default:
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("podman socket did not appear (see %s)", logPath)
		}
		time.Sleep(50 * time.Millisecond)
	}
	s.log.Write("podman-start", map[string]any{"pid": s.netnsPID})
	return s.startContainerBroker(raw)
}

func readSubIDs(path, name string, uid int) (IDRange, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return IDRange{}, fmt.Errorf("read %s: %w", path, err)
	}
	return SubIDs(data, name, uid)
}

func readInfo(r io.Reader, timeout time.Duration) (bwrapInfo, error) {
	type result struct {
		info bwrapInfo
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var info bwrapInfo
		err := json.NewDecoder(r).Decode(&info)
		if err == nil && info.ChildPID <= 0 {
			err = errors.New("no child pid in bubblewrap's status")
		}
		ch <- result{info, err}
	}()
	select {
	case res := <-ch:
		return res.info, res.err
	case <-time.After(timeout):
		return bwrapInfo{}, errors.New("timed out waiting for bubblewrap")
	}
}

// RemoveAsMapped deletes a directory that holds files owned by subordinate
// ids, such as container storage, by running rm inside the same mapping.
func RemoveAsMapped(ctx context.Context, unshare, dir string) error {
	u, err := user.Current()
	if err != nil {
		return err
	}
	subuid, err := readSubIDs("/etc/subuid", u.Username, os.Getuid())
	if err != nil {
		return err
	}
	subgid, err := readSubIDs("/etc/subgid", u.Username, os.Getuid())
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, unshare, "--user", "--map-root-user",
		fmt.Sprintf("--map-users=1:%d:%d", subuid.Start, min(subuid.Count, 65536)),
		fmt.Sprintf("--map-groups=1:%d:%d", subgid.Start, min(subgid.Count, 65536)),
		"--", "rm", "-rf", "--", dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("remove %s: %w: %s", dir, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *Session) startContainerBroker(raw string) error {
	p := s.req.Profile
	var mounts []containers.Mount
	for _, m := range p.Mounts {
		mounts = append(mounts, containers.Mount{Path: m.Path, ReadOnly: m.Mode != profile.ModeWrite, Hidden: m.Mode == profile.ModeHide})
		if m.Mode == profile.ModeWrite {
			for _, name := range jail.GitControlFiles {
				mounts = append(mounts, containers.Mount{Path: filepath.Join(m.Path, ".git", name), ReadOnly: true})
			}
		}
	}
	for _, c := range p.Caches {
		mounts = append(mounts, containers.Mount{Path: c.Path})
	}
	broker := containers.New(containers.Policy{Images: p.ContainerImages, Mounts: mounts}, raw, s.manager, s.log, containers.Config{
		Session:     s.id,
		Profile:     p.Name,
		ApprovalTTL: approvalTTL,
		Resolver:    symlinks{},
		Pins:        imagepins.NewFile(s.deps.Paths.ImagePins(p.Name)),
	})
	l, err := s.listen(PodmanSocket)
	if err != nil {
		return err
	}
	go func() { _ = broker.Serve(l) }()
	return nil
}

type symlinks struct{}

func (symlinks) EvalSymlinks(p string) (string, error) { return filepath.EvalSymlinks(p) }
