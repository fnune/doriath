package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/fnune/girdle/internal/approval"
	"github.com/fnune/girdle/internal/control"
	"github.com/fnune/girdle/internal/session"
)

// cmdRequest runs in the jail: girdle request write PATH asks you to make a
// path writable and waits for your decision.
func cmdRequest(args []string, w io.Writer) error {
	if len(args) < 2 || args[0] != "write" {
		return errors.New("request: usage: girdle request write PATH [--reason TEXT]")
	}
	flags := flag.NewFlagSet("request write", flag.ContinueOnError)
	reason := flags.String("reason", "", "why the agent needs to write there, shown to you")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	broker := os.Getenv("GIRDLE_BROKER")
	if broker == "" {
		return errors.New("request: GIRDLE_BROKER is not set; girdle request runs inside a girdle session")
	}
	path, err := filepath.Abs(args[1])
	if err != nil {
		return err
	}
	var d approval.Decision
	if err := control.Call(context.Background(), broker, session.MethodRequestWrite, session.RequestWriteParams{Path: path, Reason: *reason}, &d); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	switch d.Verdict {
	case approval.VerdictAllow:
		fmt.Fprintf(w, "%s is writable now.\n", path)
		return nil
	case approval.VerdictDeny:
		if d.Reason != "" {
			return fmt.Errorf("request: denied: %s", d.Reason)
		}
		return errors.New("request: denied")
	}
	return errors.New("request: nobody decided in time")
}

// cmdGrant runs on the host: girdle grant write PATH makes a path writable
// in a running session, until it ends.
func cmdGrant(args []string, w io.Writer) error {
	if len(args) < 2 || args[0] != "write" {
		return errors.New("grant: usage: girdle grant write PATH [--session ID]")
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
