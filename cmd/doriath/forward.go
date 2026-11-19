package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fnune/doriath/internal/cli"
	"github.com/fnune/doriath/internal/control"
	"github.com/fnune/doriath/internal/session"
)

func cmdForward(args []string) error {
	flags := flag.NewFlagSet("forward", flag.ContinueOnError)
	id := flags.String("session", "", "session to forward into (default: the only running one)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: doriath forward [--session ID] PORT[:JAIL_PORT]")
	}
	hostPort, jailPort, err := parseForward(flags.Arg(0))
	if err != nil {
		return err
	}
	_, entry, err := runningEntry(*id, func(id string) string {
		return cli.Line("forward", "--session", id, flags.Arg(0))
	})
	if err != nil {
		return err
	}
	nsenter, err := exec.LookPath("nsenter")
	if err != nil {
		return fmt.Errorf("`doriath forward` needs nsenter from util-linux: %w", err)
	}
	if err := entry.CheckHelper(nsenter); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(hostPort)))
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Printf("Forwarding 127.0.0.1:%d to port %d in the jail. Stop with Ctrl-C.\n", hostPort, jailPort)
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		<-stop
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go relayInto(conn.(*net.TCPConn), nsenter, self, entry.PID, jailPort)
	}
}

func requestForward(ctx context.Context, broker string, args []string, w io.Writer) error {
	flags := flag.NewFlagSet("request forward", flag.ContinueOnError)
	reason := flags.String("reason", "", "why the agent wants the port forwarded, shown to you")
	operands, err := parseInterspersed(flags, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return errors.New("request forward: usage: doriath request forward PORT[:JAIL_PORT] [--reason TEXT]")
	}
	hostPort, jailPort, err := parseForward(operands[0])
	if err != nil {
		return fmt.Errorf("request forward: %w", err)
	}
	var res session.RequestResult
	params := session.RequestForwardParams{HostPort: hostPort, JailPort: jailPort, Reason: *reason}
	if err := control.Call(ctx, broker, session.MethodRequestPort, params, &res); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if res.Pending != "" {
		return fmt.Errorf("request: approval %s is pending. The user sees it on the approvals page. To wait for the answer, run: %s", res.Pending, cli.Code(cli.Line("request", "wait", res.Pending)))
	}
	return reportDecision(w, res.Decision, fmt.Sprintf("Port %d in the jail is forwarded to localhost:%d on the user's machine.", jailPort, hostPort))
}

func relayInto(conn *net.TCPConn, nsenter, self string, pid, port int) {
	defer func() { _ = conn.Close() }()
	f, err := conn.File()
	if err != nil {
		fmt.Fprintf(os.Stderr, "doriath: forward: %v\n", err)
		return
	}
	defer f.Close()
	cmd := exec.Command(nsenter, "--target", strconv.Itoa(pid), "--user", "--net", "--preserve-credentials", "--",
		self, "__relay", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = f, f, os.Stderr
	cmd.Env = []string{}
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "doriath: forward: %v\n", err)
	}
}

func cmdRelay(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: doriath __relay ADDR")
	}
	client, err := net.FileConn(os.Stdin)
	if err != nil {
		return err
	}
	defer client.Close()
	upstream, err := net.Dial("tcp", args[0])
	if err != nil {
		_, port, _ := net.SplitHostPort(args[0])
		answerNothingListens(client, port)
		return err
	}
	defer upstream.Close()
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(upstream, client)
	go pipe(client, upstream)
	<-done
	<-done
	return nil
}

func parseForward(s string) (int, int, error) {
	hostPart, jailPart, found := strings.Cut(s, ":")
	if !found {
		jailPart = hostPart
	}
	host, err := strconv.Atoi(hostPart)
	if err != nil || host < 1 || host > 65535 {
		return 0, 0, fmt.Errorf("port %q: want a number from 1 to 65535", hostPart)
	}
	jail, err := strconv.Atoi(jailPart)
	if err != nil || jail < 1 || jail > 65535 {
		return 0, 0, fmt.Errorf("port %q: want a number from 1 to 65535", jailPart)
	}
	return host, jail, nil
}

func answerNothingListens(client net.Conn, port string) {
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	head := make([]byte, 16)
	n, _ := io.ReadFull(client, head)
	if !readsAsHTTP(head[:n]) {
		return
	}
	body := fmt.Sprintf("doriath: nothing listens on port %s in the jail. Start the program that serves this port, then load the page again.\n", port)
	_, _ = fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	closeWithoutReset(client)
}

func closeWithoutReset(conn net.Conn) {
	if c, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = c.CloseWrite()
	}
	_, _ = io.Copy(io.Discard, conn)
}

func readsAsHTTP(head []byte) bool {
	method, _, found := bytes.Cut(head, []byte(" "))
	if !found || len(method) == 0 {
		return false
	}
	for _, c := range method {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}
