// Package jailinit runs first inside the jail. The jail has no network, so
// it opens localhost listeners that forward to the session's unix sockets,
// then runs the agent and waits for it.
package jailinit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Forward is one localhost port inside the jail and the socket behind it.
type Forward struct {
	Port   int
	Socket string
	// Identify sends a PeerHeader before the forwarded bytes.
	Identify bool
}

func (f Forward) String() string { return fmt.Sprintf("%d=%s", f.Port, f.Socket) }

func ParseForward(s string) (Forward, error) {
	port, sock, ok := strings.Cut(s, "=")
	if !ok {
		return Forward{}, fmt.Errorf("forward %q: want PORT=SOCKET", s)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return Forward{}, fmt.Errorf("forward %q: invalid port", s)
	}
	if !strings.HasPrefix(sock, "/") {
		return Forward{}, fmt.Errorf("forward %q: socket path must be absolute", s)
	}
	return Forward{Port: n, Socket: sock}, nil
}

// Listen opens every forward before the agent starts, so the agent never
// races a listener that is not up yet.
func Listen(forwards []Forward) ([]net.Listener, error) {
	var ls []net.Listener
	for _, f := range forwards {
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(f.Port)))
		if err != nil {
			for _, open := range ls {
				_ = open.Close()
			}
			return nil, fmt.Errorf("listen on 127.0.0.1:%d: %w", f.Port, err)
		}
		ls = append(ls, l)
	}
	return ls, nil
}

func Bridge(ctx context.Context, l net.Listener, f Forward) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			var d net.Dialer
			up, err := d.DialContext(ctx, "unix", f.Socket)
			if err != nil {
				return
			}
			defer up.Close()
			if f.Identify {
				peer, _ := FindPeer("/proc", conn)
				if _, err := up.Write(PeerHeader(peer)); err != nil {
					return
				}
			}
			Splice(conn, up)
		}()
	}
}

// Splice copies both ways until both sides finish.
func Splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

// Run starts the bridges, runs argv and returns its exit code. Terminal
// signals reach the agent directly, because it shares the foreground process
// group. The others are forwarded.
func Run(forwards []Forward, argv []string) (int, error) {
	if len(argv) == 0 {
		return 2, errors.New("init: no command")
	}
	ls, err := Listen(forwards)
	if err != nil {
		return 1, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i, l := range ls {
		go Bridge(ctx, l, forwards[i])
	}

	path, err := exec.LookPath(argv[0])
	if err != nil {
		return 127, fmt.Errorf("init: %w", err)
	}
	cmd := exec.Command(path, argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTSTP)
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGWINCH)
	if err := cmd.Start(); err != nil {
		return 126, fmt.Errorf("init: start %s: %w", argv[0], err)
	}
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()
	err = cmd.Wait()
	signal.Stop(sigs)
	close(sigs)
	for _, l := range ls {
		_ = l.Close()
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return exit.ExitCode(), nil
	}
	if err != nil {
		return 1, fmt.Errorf("init: %w", err)
	}
	return 0, nil
}
