package session

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/proxy"
	"github.com/fnune/doriath/internal/term"
)

type RequestForwardParams struct {
	HostPort int    `json:"host_port"`
	JailPort int    `json:"jail_port"`
	Reason   string `json:"reason,omitempty"`
}

type hostForward struct {
	jailPort int
	name     string
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
	if err := s.checkNotApprovalsPage(hostPort); err != nil {
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
		Action:  "Forward a port into the jail",
		Facts:   portFacts(hostPort, jailPort),
		Details: forwardDetails(hostPort, jailPort),
		Note:    reason,
		Scope:   forwardScope(hostPort, jailPort),
	}
	return s.holdAndGrant(req, func() error { return s.forwardPort(hostPort, jailPort, 0) })
}

func portFacts(hostPort, jailPort int) []approval.Fact {
	facts := []approval.Fact{{Label: "Port on your machine", Value: strconv.Itoa(hostPort)}}
	if jailPort != hostPort {
		facts = append(facts, approval.Fact{Label: "Port in the jail", Value: strconv.Itoa(jailPort)})
	}
	return facts
}

const DefaultWebPort = "7341"

func (s *Session) checkNotApprovalsPage(port int) error {
	ports := []string{DefaultWebPort}
	if data, err := os.ReadFile(s.deps.Paths.WebAddr()); err == nil {
		if _, served, err := net.SplitHostPort(strings.TrimSpace(string(data))); err == nil {
			ports = append(ports, served)
		}
	}
	if slices.Contains(ports, strconv.Itoa(port)) {
		return fmt.Errorf("port %d is where doriath serves the approvals page, so the jail cannot reach it", port)
	}
	return nil
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
	if err := s.checkNotApprovalsPage(hostPort); err != nil {
		return err
	}
	if s.peers.init.Load() == 0 || s.deps.Nsenter == "" {
		return errors.New("the jail is not running, or nsenter is missing")
	}
	return s.listenForward(hostPort, jailPort, "", lasts)
}

func (s *Session) startProfileForwards() {
	for _, f := range s.req.Profile.Forwards {
		err := errors.New("nsenter is missing")
		if s.deps.Nsenter != "" {
			err = s.listenForward(f.Host, f.Jail, f.Name, 0)
		}
		if err != nil {
			s.notes = append(s.notes, note{term.Warn, fmt.Sprintf("the profile forwards port %d to the jail, but it is off this session: %v", f.Host, err)})
		}
	}
}

func (s *Session) listenForward(hostPort, jailPort int, name string, lasts time.Duration) error {
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
	f := &hostForward{jailPort: jailPort, name: name, ln: ln}
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
			go s.relayInto(conn.(*net.TCPConn), jailPort)
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
			out = append(out, StatusForward{Host: port, Jail: f.jailPort, Name: f.name})
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

func (s *Session) relayInto(conn *net.TCPConn, port int) {
	defer func() { _ = conn.Close() }()
	reaper := s.peers.reaper()
	if reaper == 0 {
		return
	}
	f, err := conn.File()
	if err != nil {
		return
	}
	defer f.Close()
	var stderr bytes.Buffer
	cmd := exec.Command(s.deps.Nsenter, "--target", strconv.Itoa(reaper), "--user", "--net", "--preserve-credentials", "--",
		s.deps.Exe, "__relay", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = f, f, &stderr
	cmd.Env = []string{}
	if err := cmd.Run(); err != nil {
		reason := strings.TrimPrefix(strings.TrimSpace(stderr.String()), "doriath: ")
		if reason == "" {
			reason = err.Error()
		}
		s.egress.Egress(proxy.Event{Kind: "error", Host: "127.0.0.1", Port: strconv.Itoa(port), Reason: reason})
	}
}
