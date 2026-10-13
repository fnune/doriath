package main

import (
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
)

func cmdForward(args []string) error {
	flags := flag.NewFlagSet("forward", flag.ContinueOnError)
	id := flags.String("session", "", "session to forward into (default: the only running one)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: girdle forward [--session ID] PORT[:JAIL_PORT]")
	}
	hostPort, jailPort, err := parseForward(flags.Arg(0))
	if err != nil {
		return err
	}
	_, entry, err := runningEntry(*id)
	if err != nil {
		return err
	}
	nsenter, err := exec.LookPath("nsenter")
	if err != nil {
		return fmt.Errorf("girdle forward needs nsenter from util-linux: %w", err)
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

func relayInto(conn *net.TCPConn, nsenter, self string, pid, port int) {
	defer func() { _ = conn.Close() }()
	f, err := conn.File()
	if err != nil {
		fmt.Fprintf(os.Stderr, "girdle: forward: %v\n", err)
		return
	}
	defer f.Close()
	cmd := exec.Command(nsenter, "--target", strconv.Itoa(pid), "--user", "--net", "--preserve-credentials", "--",
		self, "__relay", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = f, f, os.Stderr
	cmd.Env = []string{}
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "girdle: forward: %v\n", err)
	}
}

func cmdRelay(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: girdle __relay ADDR")
	}
	client, err := net.FileConn(os.Stdin)
	if err != nil {
		return err
	}
	defer client.Close()
	upstream, err := net.Dial("tcp", args[0])
	if err != nil {
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
