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
				return st, errors.New("several sessions are running; name one with --session ID (see doriath status)")
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
	fmt.Fprint(w, describeStatus(st))
	return nil
}

func describeStatus(st session.Status) string {
	var b strings.Builder
	fmt.Fprintf(&b, "This session runs in doriath profile %q (session %s).\n", st.Profile, st.Session)
	list := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(&b, "%s:\n", title)
		for _, it := range items {
			fmt.Fprintf(&b, "  - %s\n", it)
		}
	}
	list("Writable paths", st.Writable)
	list("Read-only paths", st.ReadOnly)
	list("Reachable hosts (HTTPS through the proxy)", st.Hosts)
	for _, h := range st.Intercepted {
		cred := ""
		if h.Credential {
			cred = ", with a credential the proxy adds"
		}
		fmt.Fprintf(&b, "Host %s (default %s%s):\n", h.Host, h.Default, cred)
		for _, r := range h.Rules {
			line := fmt.Sprintf("%s %s: %s", r.Method, r.Path, r.Action)
			if r.Summary != "" {
				line += " (" + r.Summary + ")"
			}
			fmt.Fprintf(&b, "  - %s\n", line)
		}
	}
	if len(st.Ports) > 0 {
		ports := make([]string, len(st.Ports))
		for i, p := range st.Ports {
			ports[i] = fmt.Sprint(p)
		}
		fmt.Fprintf(&b, "Local ports: %s\n", strings.Join(ports, ", "))
	}
	if st.Signing {
		b.WriteString("Commits are signed by an agent key through SSH_AUTH_SOCK. It signs git commits only.\n")
	}
	if st.Podman {
		b.WriteString("Containers: podman through CONTAINER_HOST. Containers share this network and the proxy.\n")
	}
	if st.Pending > 0 {
		fmt.Fprintf(&b, "Requests waiting for the user: %d\n", st.Pending)
	}
	if len(st.Denied) > 0 {
		b.WriteString("Blocked so far:\n")
		for _, d := range st.Denied {
			fmt.Fprintf(&b, "  - %s: %s (%d times)\n", d.Host, d.Reason, d.Count)
		}
	}
	b.WriteString("There is no other network access. A request to another host fails, often only as \"CONNECT tunnel failed, response 403\", " +
		"and asks the user whether to allow the host. To wait for the answer, run doriath request wait HOST, in the background if you can, then try again. " +
		"To write a path that is read-only here, run doriath request write PATH --reason TEXT, which asks the user and waits. " +
		"To change one read-only file, such as .git/config when git or jj cannot write it, write the whole new content to a file and run doriath request edit PATH --reason TEXT < FILE, then run the git or jj command again; upstream tracking and the setting jj needs for a workspace change at once. " +
		"Errors that start with \"doriath:\" come from this sandbox. Do not look for another way around a block. " +
		"If the user denies a request, tell them what was blocked and why the task needs it. Run doriath status to see this again.\n")
	return b.String()
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
