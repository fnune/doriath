package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/fnune/doriath/internal/cli"
	"github.com/fnune/doriath/internal/control"
	"github.com/fnune/doriath/internal/session"
)

func sessionStatus(ctx context.Context, id string) (session.Status, error) {
	var st session.Status
	if broker := os.Getenv("DORIATH_BROKER"); broker != "" {
		return st, control.Call(ctx, broker, session.MethodStatus, struct{}{}, &st)
	}
	p, err := paths()
	if err != nil {
		return st, err
	}
	sessions, err := liveSessions(p)
	if err != nil {
		return st, err
	}
	var target *liveSession
	for i, s := range sessions {
		if id == "" || s.info.ID == id {
			if target != nil && id == "" {
				return st, fmt.Errorf("several sessions are running; to list them, run: %s", cli.Line("status"))
			}
			target = &sessions[i]
		}
	}
	if target == nil {
		return st, errors.New("no running session")
	}
	return st, control.Call(ctx, target.control, session.MethodStatus, struct{}{}, &st)
}

func cmdStatus(args []string, w io.Writer) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	id := flags.String("session", "", "the session to describe")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return errors.New("status: usage: doriath status [--session ID]")
	}
	if *id == "" && os.Getenv("DORIATH_BROKER") == "" {
		p, err := paths()
		if err != nil {
			return err
		}
		sessions, err := liveSessions(p)
		if err != nil {
			return err
		}
		if len(sessions) != 1 {
			return listSessions(sessions, w)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := sessionStatus(ctx, *id)
	if err != nil {
		return err
	}
	fmt.Fprint(w, st.Describe())
	return nil
}

func cmdStatusline(w io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	st, err := sessionStatus(ctx, "")
	if err != nil {
		fmt.Fprintln(w, "doriath: no session")
		return nil
	}
	parts := []string{"doriath " + st.Profile, fmt.Sprintf("%d hosts", len(st.Hosts)+len(st.Intercepted))}
	if st.Pending > 0 {
		parts = append(parts, fmt.Sprintf("%d waiting for you", st.Pending))
	}
	if n := len(st.Denied); n > 0 {
		parts = append(parts, fmt.Sprintf("%d blocked", n))
	}
	fmt.Fprintln(w, strings.Join(parts, " · "))
	return nil
}
