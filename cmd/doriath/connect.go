package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/fnune/doriath/internal/cli"
	"github.com/fnune/doriath/internal/control"
	"github.com/fnune/doriath/internal/jailinit"
	"github.com/fnune/doriath/internal/session"
)

func requestConnect(ctx context.Context, broker string, args []string, w io.Writer) error {
	flags := flag.NewFlagSet("request connect", flag.ContinueOnError)
	reason := flags.String("reason", "", "why the agent wants to reach the port, shown to you")
	operands, err := parseInterspersed(flags, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return errors.New("request connect: usage: doriath request connect HOST_PORT[:JAIL_PORT] [--reason TEXT]")
	}
	hostPort, jailPort, err := parseForward(operands[0])
	if err != nil {
		return fmt.Errorf("request connect: %w", err)
	}
	var res session.RequestResult
	params := session.RequestConnectParams{HostPort: hostPort, JailPort: jailPort, Reason: *reason}
	if err := control.Call(ctx, broker, session.MethodRequestConnect, params, &res); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if res.Pending != "" {
		return fmt.Errorf("request: approval %s is pending. The user sees it on the approvals page. To wait for the answer, run: %s", res.Pending, cli.Code(cli.Line("request", "wait", res.Pending)))
	}
	return reportDecision(w, res.Decision, fmt.Sprintf("Connecting to 127.0.0.1:%d in the jail reaches 127.0.0.1:%d on the user's machine.", jailPort, hostPort))
}

func cmdConnect(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) != 2 {
		return errors.New("usage: doriath __connect JAIL_PORT SOCKET")
	}
	f, err := jailinit.ParseForward(args[0] + "=" + args[1])
	if err != nil {
		return err
	}
	ls, err := jailinit.Listen([]jailinit.Forward{f})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go jailinit.Bridge(ctx, ls[0], f)
	if _, err := fmt.Fprintln(stdout, session.ConnectReady); err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, stdin)
	return ls[0].Close()
}
