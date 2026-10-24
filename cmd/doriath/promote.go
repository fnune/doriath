package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/cli"
	"github.com/fnune/doriath/internal/control"
	"github.com/fnune/doriath/internal/edit"
	"github.com/fnune/doriath/internal/session"
)

// cmdRequest runs in the jail. doriath request write PATH asks you to make
// a path writable; doriath request wait ID waits for your answer to a
// request that is still pending.
func cmdRequest(args []string, w io.Writer) error {
	broker := os.Getenv("DORIATH_BROKER")
	if broker == "" {
		return errors.New("request: DORIATH_BROKER is not set; `doriath request` runs inside a doriath session")
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
	case len(args) >= 2 && args[0] == "edit":
		return requestEdit(ctx, broker, args[1:], os.Stdin, w)
	case len(args) >= 2 && args[0] == "write":
	default:
		return errors.New("request: usage: doriath request write PATH [--reason TEXT] | doriath request edit PATH [--reason TEXT] < NEW_CONTENT | doriath request wait ID|HOST|PATH")
	}
	flags := flag.NewFlagSet("request write", flag.ContinueOnError)
	reason := flags.String("reason", "", "why the agent needs to write there, shown to you")
	operands, err := parseInterspersed(flags, args[1:])
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return errors.New("request write: usage: doriath request write PATH [--reason TEXT]")
	}
	path, err := filepath.Abs(operands[0])
	if err != nil {
		return err
	}
	var res session.RequestWriteResult
	if err := control.Call(ctx, broker, session.MethodRequestWrite, session.RequestWriteParams{Path: path, Reason: *reason}, &res); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if res.Pending != "" {
		return fmt.Errorf("request: approval %s is pending. To wait for the answer, run: %s", res.Pending, cli.Code(cli.Line("request", "wait", res.Pending)))
	}
	return reportDecision(w, res.Decision, path+" is writable now.")
}

func requestEdit(ctx context.Context, broker string, args []string, in io.Reader, w io.Writer) error {
	flags := flag.NewFlagSet("request edit", flag.ContinueOnError)
	reason := flags.String("reason", "", "why the agent needs the change, shown to you")
	operands, err := parseInterspersed(flags, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return errors.New("request edit: usage: doriath request edit PATH [--reason TEXT] < NEW_CONTENT")
	}
	path, err := filepath.Abs(operands[0])
	if err != nil {
		return err
	}
	content, err := io.ReadAll(io.LimitReader(in, edit.MaxSize+1))
	if err != nil {
		return err
	}
	if len(content) > edit.MaxSize {
		return fmt.Errorf("request edit: the new content is larger than %d bytes", edit.MaxSize)
	}
	var res session.RequestEditResult
	if err := control.Call(ctx, broker, session.MethodRequestEdit, session.RequestEditParams{Path: path, Content: string(content), Reason: *reason}, &res); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if res.Pending != "" {
		return fmt.Errorf("request: approval %s is pending. To wait for the answer, run %s, then run `doriath request edit` again", res.Pending, cli.Code(cli.Line("request", "wait", res.Pending)))
	}
	if res.Changes == "" {
		fmt.Fprintf(w, "%s already has that content.\n", path)
		return nil
	}
	return reportDecision(w, res.Decision, "Changed "+path+":\n"+strings.TrimSuffix(res.Changes, "\n"))
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

func cmdGrant(args []string, w io.Writer) error {
	flags := flag.NewFlagSet("approvals grant", flag.ContinueOnError)
	id := flags.String("session", "", "the session, when several run")
	operands, err := parseInterspersed(flags, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return errors.New("approvals grant: usage: doriath approvals grant [--session ID] PATH")
	}
	path, err := filepath.Abs(operands[0])
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("approvals grant: %s does not exist; to give a new folder, create it first", path)
	}
	p, err := paths()
	if err != nil {
		return err
	}
	sessions, err := liveSessions(p)
	if err != nil {
		return err
	}
	dir, err := pickSession(sessions, *id, p.Sessions(), func(id string) string {
		return cli.Line("approvals", "grant", "--session", id, path)
	})
	if err != nil {
		return err
	}
	slow := time.AfterFunc(2*time.Second, func() {
		fmt.Fprintf(os.Stderr, "doriath: looking for git and jj repositories in %s before the jail can write it; a folder of many checkouts takes a while\n", path)
	})
	defer slow.Stop()
	var res session.GrantWriteResult
	if err := control.Call(context.Background(), filepath.Join(dir, session.ControlSocket), session.MethodGrantWrite, session.GrantWriteParams{Path: path}, &res); err != nil {
		return fmt.Errorf("approvals grant: %w", err)
	}
	fmt.Fprintf(w, "%s is writable in session %s until it ends.\n%s\n", path, filepath.Base(dir), res.Hint)
	return nil
}

func parseInterspersed(flags *flag.FlagSet, args []string) ([]string, error) {
	var operands []string
	for {
		if err := flags.Parse(args); err != nil {
			return nil, err
		}
		rest := flags.Args()
		if n := len(args) - len(rest); n > 0 && args[n-1] == "--" {
			return append(operands, rest...), nil
		}
		if len(rest) == 0 {
			return operands, nil
		}
		operands, args = append(operands, rest[0]), rest[1:]
	}
}
