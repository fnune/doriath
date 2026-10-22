package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/control"
	"github.com/fnune/doriath/internal/session"
)

// cmdRequest runs in the jail. doriath request write PATH asks you to make
// a path writable; doriath request wait ID waits for your answer to a
// request that is still pending.
func cmdRequest(args []string, w io.Writer) error {
	broker := os.Getenv("DORIATH_BROKER")
	if broker == "" {
		return errors.New("request: DORIATH_BROKER is not set; doriath request runs inside a doriath session")
	}
	ctx := context.Background()
	switch {
	case len(args) == 2 && args[0] == "wait":
		params, err := waitParams(args[1])
		if err != nil {
			return err
		}
		var d approval.Decision
		if err := control.Call(ctx, broker, session.MethodWait, params, &d); err != nil {
			return fmt.Errorf("request: %w", err)
		}
		return reportDecision(w, d, args[1]+" is allowed.")
	case len(args) >= 2 && args[0] == "write":
	default:
		return errors.New("request: usage: doriath request write PATH [--reason TEXT] | doriath request wait ID|HOST|PATH")
	}
	flags := flag.NewFlagSet("request write", flag.ContinueOnError)
	reason := flags.String("reason", "", "why the agent needs to write there, shown to you")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	path, err := filepath.Abs(args[1])
	if err != nil {
		return err
	}
	var res session.RequestWriteResult
	if err := control.Call(ctx, broker, session.MethodRequestWrite, session.RequestWriteParams{Path: path, Reason: *reason}, &res); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if res.Pending != "" {
		return fmt.Errorf("request: approval %s is pending. To wait for the answer, run: doriath request wait %s", res.Pending, res.Pending)
	}
	return reportDecision(w, res.Decision, path+" is writable now.")
}

// waitParams reads what a request names: a path when it has a slash or
// starts with a dot, a host when it has a dot, an id otherwise.
func waitParams(arg string) (session.WaitParams, error) {
	switch {
	case strings.Contains(arg, "/") || strings.HasPrefix(arg, "."):
		path, err := filepath.Abs(arg)
		return session.WaitParams{Path: path}, err
	case strings.Contains(arg, "."):
		return session.WaitParams{Host: arg}, nil
	}
	return session.WaitParams{ID: arg}, nil
}

func reportDecision(w io.Writer, d approval.Decision, allowed string) error {
	switch d.Verdict {
	case approval.VerdictAllow:
		fmt.Fprintln(w, allowed)
		return nil
	case approval.VerdictDeny:
		if d.Reason != "" {
			return fmt.Errorf("request: denied: %s", d.Reason)
		}
		return errors.New("request: denied")
	}
	return errors.New("request: nobody decided before the request expired")
}

// cmdGrant runs on the host: doriath grant write PATH makes a path writable
// in a running session, until it ends.
func cmdGrant(args []string, w io.Writer) error {
	if len(args) < 2 || args[0] != "write" {
		return errors.New("grant: usage: doriath grant write PATH [--session ID]")
	}
	flags := flag.NewFlagSet("grant write", flag.ContinueOnError)
	id := flags.String("session", "", "the session, when several run")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	path, err := filepath.Abs(args[1])
	if err != nil {
		return err
	}
	p, err := paths()
	if err != nil {
		return err
	}
	sessions, err := liveSessions(p)
	if err != nil {
		return err
	}
	dir, err := pickSession(sessions, *id, p.Sessions())
	if err != nil {
		return err
	}
	var res session.GrantWriteResult
	if err := control.Call(context.Background(), filepath.Join(dir, session.ControlSocket), session.MethodGrantWrite, session.GrantWriteParams{Path: path}, &res); err != nil {
		return fmt.Errorf("grant: %w", err)
	}
	fmt.Fprintf(w, "%s is writable in session %s until it ends.\n%s\n", path, filepath.Base(dir), res.Hint)
	return nil
}
