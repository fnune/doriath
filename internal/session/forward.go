package session

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"time"

	"github.com/fnune/doriath/internal/approval"
)

type RequestForwardParams struct {
	HostPort int    `json:"host_port"`
	JailPort int    `json:"jail_port"`
	Reason   string `json:"reason,omitempty"`
}

type hostForward struct {
	jailPort int
	ln       net.Listener
	expiry   *time.Timer
}

func (s *Session) requestForward(hostPort, jailPort int, reason string) (RequestResult, error) {
	if err := checkPort(hostPort); err != nil {
		return RequestResult{}, err
	}
	if err := checkPort(jailPort); err != nil {
		return RequestResult{}, err
	}
	if s.forwarding(hostPort, jailPort) {
		return RequestResult{Decision: approval.Decision{Verdict: approval.VerdictAllow}}, nil
	}
	req := approval.Request{
		Session: s.id,
		Profile: s.req.Profile.Name,
		Kind:    approval.KindForward,
		Summary: fmt.Sprintf("Forward port %d on your machine into the jail?", hostPort),
		Details: forwardDetails(hostPort, jailPort),
		Note:    reason,
		Scope:   forwardScope(hostPort, jailPort),
	}
	return s.holdAndGrant(req, func() error { return s.forwardPort(hostPort, jailPort, 0) })
}

func checkPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d: want a number from 1 to 65535", port)
	}
	return nil
}

func forwardScope(hostPort, jailPort int) string {
	return fmt.Sprintf("forward %d:%d", hostPort, jailPort)
}

func forwardDetails(hostPort, jailPort int) string {
	return fmt.Sprintf("doriath listens on 127.0.0.1:%d on your machine and relays each connection to port %d in the jail, until the session ends. "+
		"Your browser and any other program on your machine can then reach what the agent serves there.", hostPort, jailPort)
}

func (s *Session) forwarding(hostPort, jailPort int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.hostForwards[hostPort]
	return ok && f.jailPort == jailPort && f.expiry == nil
}

func (s *Session) forwardPort(hostPort, jailPort int, lasts time.Duration) error {
	reaper := int(s.peers.init.Load())
	if reaper == 0 || s.deps.Nsenter == "" {
		return errors.New("the jail is not running, or nsenter is missing")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, ok := s.hostForwards[hostPort]; ok {
		if f.jailPort != jailPort {
			return fmt.Errorf("port %d on your machine already forwards to port %d in the jail", hostPort, f.jailPort)
		}
		if lasts == 0 && f.expiry != nil {
			f.expiry.Stop()
			f.expiry = nil
		}
		return nil
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(hostPort)))
	if err != nil {
		return fmt.Errorf("listen on port %d of your machine: %w", hostPort, err)
	}
	f := &hostForward{jailPort: jailPort, ln: ln}
	if lasts > 0 {
		f.expiry = time.AfterFunc(lasts, func() { s.expireForward(hostPort, f) })
	}
	if s.hostForwards == nil {
		s.hostForwards = map[int]*hostForward{}
	}
	s.hostForwards[hostPort] = f
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.relayInto(conn.(*net.TCPConn), reaper, jailPort)
		}
	}()
	return nil
}

func (s *Session) expireForward(hostPort int, f *hostForward) {
	s.mu.Lock()
	// A lasting forward may have taken this one over while the timer fired.
	if s.hostForwards[hostPort] != f || f.expiry == nil {
		s.mu.Unlock()
		return
	}
	delete(s.hostForwards, hostPort)
	s.mu.Unlock()
	_ = f.ln.Close()
}

func (s *Session) lastingForwards() []StatusForward {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []StatusForward
	for port, f := range s.hostForwards {
		if f.expiry == nil {
			out = append(out, StatusForward{Host: port, Jail: f.jailPort})
		}
	}
	slices.SortFunc(out, func(a, b StatusForward) int { return a.Host - b.Host })
	return out
}

func (s *Session) stopForwards() {
	s.mu.Lock()
	forwards := s.hostForwards
	s.hostForwards = nil
	s.mu.Unlock()
	for _, f := range forwards {
		if f.expiry != nil {
			f.expiry.Stop()
		}
		_ = f.ln.Close()
	}
}

func (s *Session) relayInto(conn *net.TCPConn, reaper, port int) {
	defer func() { _ = conn.Close() }()
	f, err := conn.File()
	if err != nil {
		return
	}
	defer f.Close()
	cmd := exec.Command(s.deps.Nsenter, "--target", strconv.Itoa(reaper), "--user", "--net", "--preserve-credentials", "--",
		s.deps.Exe, "__relay", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = f, f, os.Stderr
	cmd.Env = []string{}
	_ = cmd.Run()
}
