package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/fnune/girdle/internal/agents/claude"
	"github.com/fnune/girdle/internal/approval"
	"github.com/fnune/girdle/internal/bundle"
	"github.com/fnune/girdle/internal/config"
	"github.com/fnune/girdle/internal/control"
	"github.com/fnune/girdle/internal/jailinit"
	"github.com/fnune/girdle/internal/landlock"
	"github.com/fnune/girdle/internal/profile"
	"github.com/fnune/girdle/internal/session"
)

type forwardFlags []jailinit.Forward

func (f *forwardFlags) String() string { return fmt.Sprint(*f) }

func (f *forwardFlags) Set(s string) error {
	fw, err := jailinit.ParseForward(s)
	if err != nil {
		return err
	}
	*f = append(*f, fw)
	return nil
}

func cmdInit(args []string) (int, error) {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	var forwards forwardFlags
	var identify intList
	flags.Var(&forwards, "forward", "PORT=SOCKET to listen on 127.0.0.1:PORT and forward to SOCKET")
	flags.Var(&identify, "identify", "PORT whose forwarded connections start with the calling program's identity")
	if err := flags.Parse(args); err != nil {
		return 2, err
	}
	for i := range forwards {
		for _, p := range identify {
			if forwards[i].Port == p {
				forwards[i].Identify = true
			}
		}
	}
	return jailinit.Run(forwards, flags.Args())
}

const maxHookInput = 1 << 20

// cmdHook runs as a Claude Code hook inside the jail. If girdle cannot get a
// decision, it prints nothing, and Claude Code shows its own prompt.
func cmdHook(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) < 2 || args[0] != "claude" {
		return errors.New("hook: usage: girdle hook claude permission-request|notification")
	}
	flags := flag.NewFlagSet("hook", flag.ContinueOnError)
	timeout := flags.Duration("timeout", time.Minute, "how long to wait for a decision")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	input, err := io.ReadAll(io.LimitReader(stdin, maxHookInput))
	if err != nil {
		return err
	}
	broker := os.Getenv("GIRDLE_BROKER")
	if broker == "" {
		return errors.New("hook: GIRDLE_BROKER is not set; is this running inside girdle?")
	}
	ctx := context.Background()
	switch args[1] {
	case "session-start":
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		st, err := sessionStatus(ctx, "")
		if err != nil {
			return err
		}
		out, err := claude.SessionStart(describeStatus(st))
		if err != nil {
			return err
		}
		_, err = stdout.Write(out)
		return err
	case "permission-request":
		req, err := claude.ParsePermissionRequest(input)
		if err != nil {
			return err
		}
		summary, details := req.Describe()
		scope := "tool " + req.ToolName
		if req.ToolName == "Bash" {
			scope += " " + details
		}
		var d approval.Decision
		ctx, cancel := context.WithTimeout(ctx, *timeout+5*time.Second)
		defer cancel()
		err = control.Call(ctx, broker, session.MethodSubmit, session.SubmitParams{
			Agent:          "claude",
			Summary:        summary,
			Details:        details,
			Scope:          scope,
			TimeoutSeconds: int(timeout.Seconds()),
		}, &d)
		if err != nil {
			fmt.Fprintln(os.Stderr, "girdle: no decision, falling back to Claude's prompt:", err)
			return nil
		}
		if d.Verdict == approval.VerdictNone {
			return nil
		}
		message := ""
		if d.Verdict == approval.VerdictDeny {
			message = "Denied by the user through girdle."
			if d.Reason != "" {
				message += " Reason: " + d.Reason
			}
		}
		out, err := claude.PermissionDecision(d.Verdict == approval.VerdictAllow, message)
		if err != nil {
			return err
		}
		_, err = stdout.Write(out)
		return err
	case "notification":
		n, err := claude.ParseNotification(input)
		if err != nil {
			return err
		}
		title := n.Title
		if title == "" {
			title = "Claude Code"
		}
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return control.Call(ctx, broker, session.MethodInform, session.InformParams{Title: title, Body: n.Message}, nil)
	}
	return fmt.Errorf("hook: unknown event %q", args[1])
}

type liveSession struct {
	info    session.Info
	control string
}

// liveSessions lists running sessions and removes the directories of
// sessions whose process is gone.
func liveSessions(p config.Paths) ([]liveSession, error) {
	entries, err := os.ReadDir(p.Sessions())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []liveSession
	for _, e := range entries {
		dir := filepath.Join(p.Sessions(), e.Name())
		data, err := os.ReadFile(filepath.Join(dir, session.InfoFile))
		if err != nil {
			continue
		}
		var info session.Info
		if json.Unmarshal(data, &info) != nil {
			continue
		}
		if syscall.Kill(info.PID, 0) != nil {
			_ = os.RemoveAll(dir)
			continue
		}
		out = append(out, liveSession{info: info, control: filepath.Join(dir, session.ControlSocket)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].info.Started.Before(out[j].info.Started) })
	return out, nil
}

type pendingRequest struct {
	approval.Request
	control string
}

func pending(ctx context.Context, p config.Paths) ([]pendingRequest, error) {
	sessions, err := liveSessions(p)
	if err != nil {
		return nil, err
	}
	var out []pendingRequest
	for _, s := range sessions {
		var reqs []approval.Request
		if err := control.Call(ctx, s.control, session.MethodList, struct{}{}, &reqs); err != nil {
			fmt.Fprintf(os.Stderr, "girdle: session %s does not answer: %v\n", s.info.ID, err)
			continue
		}
		for _, r := range reqs {
			out = append(out, pendingRequest{Request: r, control: s.control})
		}
	}
	return out, nil
}

func cmdApprovals(args []string) error {
	p, err := paths()
	if err != nil {
		return err
	}
	ctx := context.Background()
	sub := "list"
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "list":
		reqs, err := pending(ctx, p)
		if err != nil {
			return err
		}
		printPending(os.Stdout, reqs, time.Now())
		return nil
	case "allow", "deny":
		flags := flag.NewFlagSet(sub, flag.ContinueOnError)
		lasting := flags.String("for", "once", "once, session, or a duration such as 30m")
		reason := flags.String("reason", "", "a reason the agent sees")
		if len(args) == 0 {
			return fmt.Errorf("approvals %s: name the request id", sub)
		}
		id := args[0]
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		d := approval.Decision{Verdict: approval.VerdictDeny, By: "cli", Reason: *reason}
		if sub == "allow" {
			d, err = allowDecision(*lasting, time.Now())
			if err != nil {
				return err
			}
		}
		return decide(ctx, p, id, d)
	case "watch":
		return watch(ctx, p, os.Stdin, os.Stdout)
	}
	return fmt.Errorf("approvals: unknown subcommand %q", sub)
}

func allowDecision(lasting string, now time.Time) (approval.Decision, error) {
	d := approval.Decision{Verdict: approval.VerdictAllow, By: "cli"}
	switch lasting {
	case "once":
		d.Lasting = approval.LastingOnce
	case "session":
		d.Lasting = approval.LastingSession
	default:
		dur, err := time.ParseDuration(lasting)
		if err != nil || dur <= 0 {
			return d, fmt.Errorf("--for %q: want once, session or a duration such as 30m", lasting)
		}
		d.Lasting, d.Until = approval.LastingUntil, now.Add(dur)
	}
	return d, nil
}

func decide(ctx context.Context, p config.Paths, id string, d approval.Decision) error {
	reqs, err := pending(ctx, p)
	if err != nil {
		return err
	}
	for _, r := range reqs {
		if r.ID == id {
			return control.Call(ctx, r.control, session.MethodDecide, session.DecideParams{ID: id, Decision: d}, nil)
		}
	}
	return fmt.Errorf("no pending request %s; run girdle approvals to list them", id)
}

func printPending(w io.Writer, reqs []pendingRequest, now time.Time) {
	if len(reqs) == 0 {
		fmt.Fprintln(w, "No pending requests.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPROFILE\tSESSION\tEXPIRES IN\tREQUEST")
	for _, r := range reqs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.Profile, r.Session, r.Expires.Sub(now).Round(time.Second), r.Summary)
	}
	_ = tw.Flush()
	for _, r := range reqs {
		if r.Details != "" {
			fmt.Fprintf(w, "\n%s: %s\n", r.ID, indent(r.Details))
		}
	}
}

func indent(s string) string { return strings.ReplaceAll(s, "\n", "\n    ") }

// watch asks about each new request in the terminal, for people who keep a
// terminal open next to their agents instead of using notifications.
func watch(ctx context.Context, p config.Paths, in io.Reader, out io.Writer) error {
	asked := map[string]bool{}
	lines := bufio.NewScanner(in)
	fmt.Fprintln(out, "Watching for requests. Press Ctrl+C to stop.")
	for {
		reqs, err := pending(ctx, p)
		if err != nil {
			return err
		}
		for _, r := range reqs {
			if asked[r.ID] {
				continue
			}
			asked[r.ID] = true
			fmt.Fprintf(out, "\n[%s] %s (profile %s)\n", r.ID, r.Summary, r.Profile)
			if r.Details != "" {
				fmt.Fprintf(out, "    %s\n", indent(r.Details))
			}
			fmt.Fprint(out, "Allow [o]nce, allow for this [s]ession, [d]eny, or [Enter] to skip: ")
			if !lines.Scan() {
				return lines.Err()
			}
			var d approval.Decision
			switch strings.TrimSpace(strings.ToLower(lines.Text())) {
			case "o":
				d = approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingOnce, By: "cli"}
			case "s":
				d = approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingSession, By: "cli"}
			case "d":
				d = approval.Decision{Verdict: approval.VerdictDeny, By: "cli"}
			default:
				continue
			}
			if err := control.Call(ctx, r.control, session.MethodDecide, session.DecideParams{ID: r.ID, Decision: d}, nil); err != nil {
				fmt.Fprintln(out, "Could not decide:", err)
			}
		}
		time.Sleep(time.Second)
	}
}

func cmdSessions() error {
	p, err := paths()
	if err != nil {
		return err
	}
	sessions, err := liveSessions(p)
	if err != nil {
		return err
	}
	if len(sessions) == 0 {
		fmt.Println("No running sessions.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPROFILE\tSTARTED\tDIRECTORY\tCOMMAND")
	for _, s := range sessions {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.info.ID, s.info.Profile, s.info.Started.Format("15:04"), s.info.Cwd, strings.Join(s.info.Command, " "))
	}
	return tw.Flush()
}

func cmdProfiles(args []string) error {
	p, err := paths()
	if err != nil {
		return err
	}
	l := loader(p)
	if len(args) == 0 || args[0] == "list" {
		names, err := l.Names()
		if err != nil {
			return err
		}
		if len(names) == 0 {
			fmt.Printf("No profiles in %s.\n", p.Profiles())
			return nil
		}
		for _, n := range names {
			prof, err := l.Load(n)
			if err != nil {
				fmt.Printf("%s\t(error: %v)\n", n, err)
				continue
			}
			fmt.Printf("%s\t%s\n", n, prof.Description)
		}
		return nil
	}
	if args[0] == "which" {
		return profilesWhich(l, args[1:])
	}
	if args[0] == "show" && len(args) == 2 {
		prof, err := l.Load(args[1])
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(prof)
	}
	return errors.New("profiles: usage: girdle profiles [list | show NAME]")
}

func cmdDoctor() int {
	failed := false
	check := func(name string, err error) {
		if err != nil {
			failed = true
			fmt.Printf("problem  %s: %v\n", name, err)
			return
		}
		fmt.Printf("ok       %s\n", name)
	}
	note := func(name, msg string) { fmt.Printf("note     %s: %s\n", name, msg) }

	p, err := paths()
	check("directories", err)
	if err != nil {
		return 1
	}
	user, err := config.LoadUser(p.UserConfig(), p.Home)
	check("config "+p.UserConfig(), err)
	bwrap, err := bundle.Bwrap(p.Bundle(), os.Getenv)
	if bundle.Bundled() {
		check("bundled bubblewrap", err)
	} else {
		check("bubblewrap from the system (development build)", err)
	}
	if err == nil {
		out, runErr := exec.Command(bwrap, "--unshare-all", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "true").CombinedOutput()
		if runErr != nil {
			runErr = fmt.Errorf("%w: %s (are unprivileged user namespaces enabled?)", runErr, strings.TrimSpace(string(out)))
		}
		check("unprivileged user namespaces", runErr)
	}
	names, err := loader(p).Names()
	check("profiles in "+p.Profiles(), err)
	for _, n := range names {
		_, err := loader(p).Load(n)
		check("profile "+n, err)
	}
	if len(names) == 0 {
		note("profiles", "none yet; see docs/install.md")
	}
	note("secrets", fmt.Sprintf("%d configured; girdle fetches them when a session first needs them", len(user.Secrets)))
	for _, tool := range []string{"unshare", "nsenter", "podman", "newuidmap"} {
		if lookPath(tool) == "" {
			note(tool, "not found; the podman module needs it")
		}
	}
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		note("desktop notifications", "no session bus; approvals work through girdle approvals only")
	}
	if failed {
		return 1
	}
	return 0
}

// cmdClean deletes a profile's caches. Container storage holds files owned by
// subordinate ids, which a plain rm cannot remove.
func cmdClean(args []string) error {
	if len(args) != 1 {
		return errors.New("clean: usage: girdle clean PROFILE")
	}
	name := args[0]
	p, err := paths()
	if err != nil {
		return err
	}
	if _, err := loader(p).Load(name); err != nil {
		return err
	}
	sessions, err := liveSessions(p)
	if err != nil {
		return err
	}
	for _, s := range sessions {
		if s.info.Profile == name {
			return fmt.Errorf("session %s of profile %s is running; stop it first", s.info.ID, name)
		}
	}
	dir := p.AgentCache(name)
	containers := filepath.Join(dir, "containers")
	if _, err := os.Stat(containers); err == nil {
		unshare := lookPath("unshare")
		if unshare == "" {
			return errors.New("clean: container storage needs util-linux unshare to remove")
		}
		if err := session.RemoveAsMapped(context.Background(), unshare, containers); err != nil {
			return err
		}
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove %s: %w", dir, err)
	}
	fmt.Printf("Removed the caches of profile %s.\n", name)
	return nil
}

// profilesWhich prints the profile that girdle run would pick, for shell
// shims that run an agent through girdle when a profile matches. With -q it
// prints nothing and only sets the exit status.
func profilesWhich(l *profile.Loader, args []string) error {
	flags := flag.NewFlagSet("which", flag.ContinueOnError)
	quiet := flags.Bool("q", false, "print nothing, only set the exit status")
	if err := flags.Parse(args); err != nil {
		return err
	}
	dir := flags.Arg(0)
	if dir == "" {
		var err error
		if dir, err = os.Getwd(); err != nil {
			return err
		}
	}
	p, err := l.Find(dir)
	if err != nil {
		if *quiet {
			os.Exit(1)
		}
		return err
	}
	if !*quiet {
		fmt.Println(p.Name)
	}
	return nil
}

type intList []int

func (l *intList) String() string { return fmt.Sprint(*l) }

func (l *intList) Set(s string) error {
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("%q is not a port number", s)
	}
	*l = append(*l, n)
	return nil
}

type stringList []string

func (l *stringList) String() string { return fmt.Sprint(*l) }

func (l *stringList) Set(s string) error {
	*l = append(*l, s)
	return nil
}

// cmdSandboxExec limits writes to the given paths with Landlock and then
// becomes the command, so the limit holds for it and everything it starts.
func cmdSandboxExec(args []string) error {
	flags := flag.NewFlagSet("sandbox-exec", flag.ContinueOnError)
	var writable stringList
	flags.Var(&writable, "writable", "a path the command may write beneath")
	if err := flags.Parse(args); err != nil {
		return err
	}
	argv := flags.Args()
	if len(argv) == 0 {
		return errors.New("sandbox-exec: no command")
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return fmt.Errorf("sandbox-exec: %w", err)
	}
	err = landlock.Exec(writable, path, argv, os.Environ())
	if errors.Is(err, landlock.ErrUnsupported) {
		fmt.Fprintln(os.Stderr, "girdle: this kernel has no Landlock; writes are limited by the mounts only")
		return syscall.Exec(path, argv, os.Environ())
	}
	return fmt.Errorf("sandbox-exec: %w", err)
}
