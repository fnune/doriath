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
	case len(args) >= 2 && args[0] == "host":
		return requestHost(ctx, broker, args[1:], w)
	case len(args) >= 2 && args[0] == "open":
		return requestOpen(ctx, broker, args[1:], w)
	case len(args) >= 2 && args[0] == "module":
		return requestModule(ctx, broker, args[1:], w)
	case len(args) >= 2 && args[0] == "forward":
		return requestForward(ctx, broker, args[1:], w)
	case len(args) >= 2 && (args[0] == "write" || args[0] == "read"):
	default:
		return errors.New("request: usage: doriath request write PATH [--reason TEXT] | doriath request read PATH [--reason TEXT] | doriath request module MODULE PATH [--reason TEXT] | doriath request host HOST [--reason TEXT] | doriath request open URL|PATH [--reason TEXT] | doriath request forward PORT[:JAIL_PORT] [--reason TEXT] | doriath request edit PATH [--reason TEXT] < NEW_CONTENT | doriath request wait ID|HOST|PATH")
	}
	verb := args[0]
	flags := flag.NewFlagSet("request "+verb, flag.ContinueOnError)
	reason := flags.String("reason", "", "why the agent needs the path, shown to you")
	operands, err := parseInterspersed(flags, args[1:])
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return fmt.Errorf("request %s: usage: doriath request %s PATH [--reason TEXT]", verb, verb)
	}
	path, err := filepath.Abs(operands[0])
	if err != nil {
		return err
	}
	method, params, granted := session.MethodRequestWrite, any(session.RequestWriteParams{Path: path, Reason: *reason}), path+" is writable now."
	if verb == "read" {
		method, params, granted = session.MethodRequestRead, session.RequestReadParams{Path: path, Reason: *reason}, path+" is readable now."
	}
	var res session.RequestResult
	if err := control.Call(ctx, broker, method, params, &res); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if res.Pending != "" {
		return fmt.Errorf("request: approval %s is pending. The user sees it on the approvals page. To wait for the answer, run: %s", res.Pending, cli.Code(cli.Line("request", "wait", res.Pending)))
	}
	return reportDecision(w, res.Decision, granted)
}

func requestHost(ctx context.Context, broker string, args []string, w io.Writer) error {
	flags := flag.NewFlagSet("request host", flag.ContinueOnError)
	reason := flags.String("reason", "", "why the agent needs the host, shown to you")
	operands, err := parseInterspersed(flags, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return errors.New("request host: usage: doriath request host HOST [--reason TEXT]")
	}
	var res session.RequestResult
	if err := control.Call(ctx, broker, session.MethodRequestHost, session.RequestHostParams{Host: operands[0], Reason: *reason}, &res); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if res.Pending != "" {
		return fmt.Errorf("request: approval %s is pending. The user sees it on the approvals page. To wait for the answer, run: %s", res.Pending, cli.Code(cli.Line("request", "wait", res.Pending)))
	}
	return reportDecision(w, res.Decision, operands[0]+" is reachable now.")
}

func requestModule(ctx context.Context, broker string, args []string, w io.Writer) error {
	flags := flag.NewFlagSet("request module", flag.ContinueOnError)
	reason := flags.String("reason", "", "why the agent needs the module in the repository, shown to you")
	operands, err := parseInterspersed(flags, args)
	if err != nil {
		return err
	}
	if len(operands) != 2 {
		return errors.New("request module: usage: doriath request module MODULE PATH [--reason TEXT]")
	}
	path, err := filepath.Abs(operands[1])
	if err != nil {
		return err
	}
	var res session.RequestResult
	if err := control.Call(ctx, broker, session.MethodRequestModule, session.RequestModuleParams{Module: operands[0], Path: path, Reason: *reason}, &res); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if res.Pending != "" {
		return fmt.Errorf("request: approval %s is pending. The user sees it on the approvals page. To wait for the answer, run: %s", res.Pending, cli.Code(cli.Line("request", "wait", res.Pending)))
	}
	return reportDecision(w, res.Decision, "Module "+operands[0]+" applies in the repository of "+path+" now.")
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
