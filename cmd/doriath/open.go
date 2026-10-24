package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/fnune/doriath/internal/cli"
	"github.com/fnune/doriath/internal/control"
	"github.com/fnune/doriath/internal/session"
)

func requestOpen(ctx context.Context, broker string, args []string, w io.Writer) error {
	flags := flag.NewFlagSet("request open", flag.ContinueOnError)
	reason := flags.String("reason", "", "why the agent wants the link open, shown to you")
	operands, err := parseInterspersed(flags, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return errors.New("request open: usage: doriath request open URL [--reason TEXT]")
	}
	var res session.RequestResult
	if err := control.Call(ctx, broker, session.MethodRequestOpen, session.RequestOpenParams{URL: operands[0], Reason: *reason}, &res); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if res.Pending != "" {
		return fmt.Errorf("request: approval %s is pending. The user sees it on the approvals page. To wait for the answer, run: %s", res.Pending, cli.Code(cli.Line("request", "wait", res.Pending)))
	}
	return reportDecision(w, res.Decision, "The link is open in the user's browser.")
}

func cmdOpenFront(args []string) int {
	broker := os.Getenv("DORIATH_BROKER")
	if broker == "" || len(args) != 1 {
		fmt.Fprintln(os.Stderr, "doriath: this xdg-open opens one http or https link in your browser, from a doriath session")
		return 1
	}
	if err := requestOpen(context.Background(), broker, args, io.Discard); err != nil {
		fmt.Fprintln(os.Stderr, "doriath:", err)
		return 1
	}
	return 0
}

func openOnHost(url string) error {
	cmd := exec.Command("xdg-open", url)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
