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

	"github.com/fnune/girdle/internal/jail"
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

func ContainersConf(tmpDir string) []byte {
	return []byte(fmt.Sprintf(`# Written by girdle for one session.
[containers]
# Containers share the session's network namespace: they reach the internet
# only through the proxy, and the agent reaches their ports on localhost.
netns = "host"
cgroups = "disabled"
http_proxy = true

[engine]
cgroup_manager = "cgroupfs"
events_logger = "file"
image_copy_tmp_dir = %s
`, quote(tmpDir)))
}

func StorageConf(graphRoot string) []byte {
	return []byte(fmt.Sprintf(`# Written by girdle for one session.
[storage]
driver = "overlay"
graphroot = %s
runroot = "/run/containers/storage"
`, quote(graphRoot)))
}

type bwrapInfo struct {
	ChildPID int `json:"child-pid"`
}

// startPodman runs a podman service as root in a user namespace that maps the
// user's subordinate ids. It sees the same paths as the agent's jail, so
// containers can mount the worktree and nothing else. Its network namespace
// becomes the session's: the agent joins it, and the service's init process
// holds the proxy and port forwards for both.
func (s *Session) startPodman(ctx context.Context) error {
	if s.deps.Unshare == "" || s.deps.Podman == "" {
		return errors.New("the podman module needs util-linux unshare and podman on PATH")
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
	if err := writeFile(s.jailPath("containers.conf"), ContainersConf(filepath.Join(root, "tmp")), 0o644); err != nil {
		return err
	}
	if err := writeFile(s.jailPath("storage.conf"), StorageConf(filepath.Join(root, "storage")), 0o644); err != nil {
		return err
	}

	p := s.req.Profile
	argv := []string{jail.ExePath, "init"}
	for _, f := range s.forwards() {
		argv = append(argv, "--forward", f)
	}
	argv = append(argv, "--", s.deps.Podman, "system", "service", "--time=0", "unix://"+jail.InJail(PodmanSocket))
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", jail.ProxyPort)
	spec, err := jail.Plan(p, s.layout(), jail.Options{
		UID:     0,
		Home:    s.deps.Paths.Home,
		Cwd:     s.req.Cwd,
		Command: argv,
		HostEnv: envMap(s.deps.Environ),
		ExtraEnv: map[string]string{
			"HTTP_PROXY":              proxyURL,
			"HTTPS_PROXY":             proxyURL,
			"NO_PROXY":                "localhost,127.0.0.1,::1",
			"SSL_CERT_FILE":           jail.InJail("ca-bundle.pem"),
			"CONTAINERS_CONF":         jail.InJail("containers.conf"),
			"CONTAINERS_STORAGE_CONF": jail.InJail("storage.conf"),
		},
		SkipUserNS:      true,
		InfoFD:          3,
		JailDirWritable: true,
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
	logFile, err := os.OpenFile(filepath.Join(s.dir, "podman.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	cmd := exec.Command(s.deps.Unshare, append(unshareArgs, spec.Args()...)...)
	cmd.Env = []string{}
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
		return fmt.Errorf("podman service did not start: %w (see %s)", err, filepath.Join(s.dir, "podman.log"))
	}
	s.netns = fmt.Sprintf("/proc/%d/ns/net", info.ChildPID)

	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(s.jailPath(PodmanSocket)); err == nil {
			break
		}
		select {
		case err := <-waited:
			waited <- err
			return fmt.Errorf("podman service exited: %v (see %s)", err, filepath.Join(s.dir, "podman.log"))
		default:
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("podman socket did not appear (see %s)", filepath.Join(s.dir, "podman.log"))
		}
		time.Sleep(50 * time.Millisecond)
	}
	s.log.Write("podman-start", map[string]any{"netns": s.netns})
	return nil
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
