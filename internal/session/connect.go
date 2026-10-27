package session

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/fnune/doriath/internal/approval"
)

type RequestConnectParams struct {
	HostPort int `json:"host_port"`
	JailPort int `json:"jail_port"`
	// Reason is the agent's own text, shown to you as such.
	Reason string `json:"reason,omitempty"`
}

// ConnectReady is the line that `doriath __connect` prints once it listens.
const ConnectReady = "ready"

const connectStartTimeout = 5 * time.Second

// hostConnect makes a port of the jail reach a port of your machine. The
// jail has no network, so a helper in its network namespace listens on the
// jail port and relays each connection to a socket of the session, and the
// session connects that socket to your machine.
type hostConnect struct {
	hostPort int
	ln       net.Listener
	helper   *exec.Cmd
	// stdin closes when the session ends or dies, which stops the helper.
	stdin  io.Closer
	cancel context.CancelFunc
}

func (s *Session) requestConnect(hostPort, jailPort int, reason string) (RequestResult, error) {
	if err := checkPort(hostPort); err != nil {
		return RequestResult{}, err
	}
	if err := checkPort(jailPort); err != nil {
		return RequestResult{}, err
	}
	if s.connecting(hostPort, jailPort) {
		return RequestResult{Decision: approval.Decision{Verdict: approval.VerdictAllow}}, nil
	}
	req := approval.Request{
		Session: s.id,
		Profile: s.req.Profile.Name,
		Kind:    approval.KindConnect,
		Summary: fmt.Sprintf("Let the jail connect to port %d on your machine?", hostPort),
		Details: connectDetails(hostPort, jailPort),
		Note:    reason,
		Scope:   connectScope(hostPort, jailPort),
	}
	return s.holdAndGrant(req, func() error { return s.connectPort(hostPort, jailPort) })
}

func connectScope(hostPort, jailPort int) string {
	return fmt.Sprintf("connect %d:%d", hostPort, jailPort)
}

func connectDetails(hostPort, jailPort int) string {
	return fmt.Sprintf("Each connection that a program in the jail makes to 127.0.0.1:%d reaches 127.0.0.1:%d on your machine, until the session ends. "+
		"The service there sees a client on your loopback address, and may trust it as it trusts your own programs, such as a database tunnel that is already signed in. "+
		"Only this TCP port is open. The agent reaches no other port of your machine.", jailPort, hostPort)
}

// connecting reports whether jailPort already reaches hostPort, through a
// connect of the session or a tcp_ports entry of the profile.
func (s *Session) connecting(hostPort, jailPort int) bool {
	if hostPort == jailPort && slices.Contains(s.req.Profile.Egress.TCPPorts, hostPort) {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.hostConnects[jailPort]
	return ok && c.hostPort == hostPort
}

// connectPort opens jailPort in the jail to hostPort of your machine until
// the session ends.
func (s *Session) connectPort(hostPort, jailPort int) error {
	reaper := int(s.peers.init.Load())
	if reaper == 0 || s.deps.Nsenter == "" {
		return errors.New("the jail is not running, or nsenter is missing")
	}
	for _, f := range s.req.Profile.Egress.Forwards() {
		if f.Port == jailPort && (!f.TCP || f.Port != hostPort) {
			return fmt.Errorf("port %d in the jail is already used by the profile", jailPort)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.hostConnects[jailPort]; ok {
		if c.hostPort != hostPort {
			return fmt.Errorf("port %d in the jail already reaches port %d on your machine", jailPort, c.hostPort)
		}
		return nil
	}
	socket := s.jailPath(fmt.Sprintf("connect-%d.sock", jailPort))
	_ = os.Remove(socket)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", socket, err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("protect %s: %w", socket, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &hostConnect{hostPort: hostPort, ln: ln, cancel: cancel}
	if err := s.startConnectHelper(c, reaper, jailPort, socket); err != nil {
		c.stop()
		return err
	}
	if s.hostConnects == nil {
		s.hostConnects = map[int]*hostConnect{}
	}
	s.hostConnects[jailPort] = c
	go s.relayToHost(ctx, ln, hostPort)
	return nil
}

func (s *Session) startConnectHelper(c *hostConnect, reaper, jailPort int, socket string) error {
	cmd := exec.Command(s.deps.Nsenter, "--target", strconv.Itoa(reaper), "--user", "--net", "--preserve-credentials", "--",
		s.deps.Exe, "__connect", strconv.Itoa(jailPort), socket)
	cmd.Env = []string{}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start the helper: %w", err)
	}
	c.helper, c.stdin = cmd, stdin
	ready := make(chan bool, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- strings.TrimSpace(line) == ConnectReady
	}()
	select {
	case ok := <-ready:
		if ok {
			return nil
		}
		_ = cmd.Wait()
		return fmt.Errorf("listen on port %d in the jail: %s", jailPort, strings.TrimSpace(stderr.String()))
	case <-time.After(connectStartTimeout):
		return fmt.Errorf("listen on port %d in the jail: the helper did not start", jailPort)
	}
}

func (c *hostConnect) stop() {
	c.cancel()
	_ = c.ln.Close()
	if c.stdin != nil {
		_ = c.stdin.Close()
	}
	if c.helper != nil && c.helper.Process != nil {
		_ = c.helper.Process.Kill()
		_ = c.helper.Wait()
	}
}

// connections are the connects of the session, as host and jail port pairs
// sorted by jail port.
func (s *Session) connections() []StatusForward {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []StatusForward
	for jailPort, c := range s.hostConnects {
		out = append(out, StatusForward{Host: c.hostPort, Jail: jailPort})
	}
	slices.SortFunc(out, func(a, b StatusForward) int { return a.Jail - b.Jail })
	return out
}

func (s *Session) stopConnects() {
	s.mu.Lock()
	connects := s.hostConnects
	s.hostConnects = nil
	s.mu.Unlock()
	for _, c := range connects {
		c.stop()
	}
}
