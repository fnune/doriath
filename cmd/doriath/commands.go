package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/fnune/doriath/internal/notify"
	"github.com/fnune/doriath/internal/oauth"
	"github.com/fnune/doriath/internal/seccomp"
	"github.com/fnune/doriath/internal/secret"

	"github.com/fnune/doriath/internal/agents/claude"
	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/bundle"
	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/confine"
	"github.com/fnune/doriath/internal/control"
	"github.com/fnune/doriath/internal/jailinit"
	"github.com/fnune/doriath/internal/landlock"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/session"

	"golang.org/x/sys/unix"
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
	forwards, command, err := parseInit(args)
	if err != nil {
		return 2, err
	}
	return jailinit.Run(forwards, command)
}

func parseInit(args []string) ([]jailinit.Forward, []string, error) {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	var forwards forwardFlags
	var identify intList
	flags.Var(&forwards, "forward", "PORT=SOCKET to listen on 127.0.0.1:PORT and forward to SOCKET")
	flags.Var(&identify, "identify", "PORT whose forwarded connections start with the calling program's identity")
	if err := flags.Parse(args); err != nil {
		return nil, nil, err
	}
	for i := range forwards {
		for _, p := range identify {
			if forwards[i].Port == p {
				forwards[i].Identify = true
			}
		}
	}
	return forwards, flags.Args(), nil
}

const maxHookInput = 1 << 20

func cmdHook(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) < 2 || args[0] != "claude" {
		return errors.New("hook: usage: doriath hook claude permission-request|notification")
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
	broker := os.Getenv("DORIATH_BROKER")
	if broker == "" {
		return errors.New("hook: DORIATH_BROKER is not set; is this running inside doriath?")
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
			fmt.Fprintln(os.Stderr, "doriath: no decision, falling back to Claude's prompt:", err)
			return nil
		}
		if d.Verdict == approval.VerdictNone {
			return nil
		}
		message := ""
		if d.Verdict == approval.VerdictDeny {
			message = "Denied by the user through doriath."
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
			fmt.Fprintf(os.Stderr, "doriath: session %s does not answer: %v\n", s.info.ID, err)
			continue
		}
		for _, r := range reqs {
			out = append(out, pendingRequest{Request: r, control: s.control})
		}
	}
	return out, nil
}

func cmdApprovals(ctx context.Context, args []string, c clock, stdin io.Reader, stdout io.Writer) error {
	p, err := paths()
	if err != nil {
		return err
	}
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
		printPending(stdout, reqs, c.Now())
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
			d, err = allowDecision(*lasting, c.Now())
			if err != nil {
				return err
			}
		}
		return decide(ctx, p, id, d)
	case "watch":
		return watch(ctx, p, c, stdin, stdout)
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
	var match []pendingRequest
	for _, r := range reqs {
		if r.ID == id {
			match = append(match, r)
		}
	}
	switch len(match) {
	case 0:
		return fmt.Errorf("no pending request %s; run doriath approvals to list them", id)
	case 1:
		return control.Call(ctx, match[0].control, session.MethodDecide, session.DecideParams{ID: id, Decision: d}, nil)
	}
	return fmt.Errorf("sessions %s and %s both have a request %s; decide it from its notification", match[0].Session, match[1].Session, id)
}

func printPending(w io.Writer, reqs []pendingRequest, now time.Time) {
	if len(reqs) == 0 {
		fmt.Fprintln(w, "No pending requests.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPROFILE\tSESSION\tEXPIRES IN\tREQUEST")
	for _, r := range reqs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.Profile, r.Session, r.Expires.Sub(now).Round(time.Second), session.Printable(r.Summary))
	}
	_ = tw.Flush()
	for _, r := range reqs {
		if r.Details != "" {
			fmt.Fprintf(w, "\n%s: %s\n", r.ID, indent(session.Printable(r.Details)))
		}
	}
}

func indent(s string) string { return strings.ReplaceAll(s, "\n", "\n    ") }

func watch(ctx context.Context, p config.Paths, c clock, in io.Reader, out io.Writer) error {
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
			fmt.Fprintf(out, "\n[%s] %s (profile %s)\n", r.ID, session.Printable(r.Summary), r.Profile)
			if r.Details != "" {
				fmt.Fprintf(out, "    %s\n", indent(session.Printable(r.Details)))
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
		select {
		case <-ctx.Done():
			return nil
		case <-c.After(time.Second):
		}
	}
}

func cmdSessions(w io.Writer) error {
	p, err := paths()
	if err != nil {
		return err
	}
	sessions, err := liveSessions(p)
	if err != nil {
		return err
	}
	if len(sessions) == 0 {
		fmt.Fprintln(w, "No running sessions.")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPROFILE\tSTARTED\tDIRECTORY\tCOMMAND")
	for _, s := range sessions {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.info.ID, s.info.Profile, s.info.Started.Format("15:04"), s.info.Cwd, strings.Join(s.info.Command, " "))
	}
	return tw.Flush()
}

func cmdProfiles(args []string, stdin io.Reader, stdout io.Writer) error {
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
			fmt.Fprintf(stdout, "No profiles in %s.\n", p.Profiles())
			return nil
		}
		for _, n := range names {
			prof, err := l.Load(n)
			if err != nil {
				fmt.Fprintf(stdout, "%s\t(error: %v)\n", n, err)
				continue
			}
			fmt.Fprintf(stdout, "%s\t%s\n", n, prof.Description)
		}
		return nil
	}
	if args[0] == "edit" && len(args) == 2 {
		return profilesEdit(l, p.Profiles(), args[1], stdin, stdout)
	}
	if args[0] == "show" && len(args) == 2 {
		prof, err := l.Load(args[1])
		if err != nil {
			return err
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(prof)
	}
	return errors.New("profiles: usage: doriath profiles [list | show NAME | edit NAME]")
}

func cmdDoctor(args []string, w io.Writer) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fetch := flags.Bool("secrets", false, "also fetch every secret once, which can prompt for an unlock")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	failed := false
	check := func(name string, err error) {
		if err != nil {
			failed = true
			fmt.Fprintf(w, "problem  %s: %v\n", name, err)
			return
		}
		fmt.Fprintf(w, "ok       %s\n", name)
	}
	note := func(name, msg string) { fmt.Fprintf(w, "note     %s: %s\n", name, msg) }

	p, err := paths()
	check("directories", err)
	if err != nil {
		return 1
	}
	_, err = config.LoadUser(p.UserConfig())
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
	_, err = seccomp.HostArch()
	check("seccomp filter for this architecture", err)
	if abi, err := landlock.ABI(); err != nil {
		note("landlock", "not available; writes are limited by the mounts only")
	} else {
		check(fmt.Sprintf("landlock (ABI %d)", abi), nil)
	}

	l := loader(p)
	names, err := l.Names()
	check("profiles in "+p.Profiles(), err)
	podman := false
	var profiles []*profile.Profile
	for _, n := range names {
		prof, err := l.Load(n)
		check("profile "+n, err)
		if err == nil {
			profiles = append(profiles, prof)
			podman = podman || prof.Podman
		}
	}
	if len(names) == 0 {
		note("profiles", "none yet; see docs/install.md")
	}

	secrets := 0
	for _, prof := range profiles {
		store := secret.NewConfigured(prof.Secrets, execRunner{}, secret.OSFiles{}).WithOAuth(oauth.NewTokens(p.State, prof.Name))
		for _, name := range slices.Sorted(maps.Keys(prof.Secrets)) {
			secrets++
			label := "secret " + prof.Name + "/" + name
			b := prof.Secrets[name]
			switch {
			case *fetch:
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				_, err := store.Get(ctx, name)
				cancel()
				check(label, err)
			case b.OAuth != nil:
				_, err := os.Stat(oauth.StatePath(p.State, prof.Name, name))
				if errors.Is(err, os.ErrNotExist) {
					err = fmt.Errorf("not signed in: run doriath login --profile %s %s", prof.Name, name)
				}
				check(label+" (oauth)", err)
			case b.File != "":
				info, err := os.Stat(b.File)
				if err == nil && info.Mode().Perm()&0o077 != 0 {
					err = fmt.Errorf("%s is readable by other users: run chmod 600 on it", b.File)
				}
				check(label+" (file)", err)
			default:
				_, err := exec.LookPath(b.Command[0])
				check(label+" (command "+b.Command[0]+")", err)
			}
		}
	}
	if !*fetch && secrets > 0 {
		note("secrets", "run doriath doctor --secrets to fetch each one once")
	}

	if podman {
		for _, tool := range []string{"unshare", "nsenter", "podman", "newuidmap"} {
			if lookPath(tool) == "" {
				check(tool, fmt.Errorf("not found; the podman module needs it"))
			}
		}
		if u, err := osuser.Current(); err == nil {
			for _, f := range []string{"/etc/subuid", "/etc/subgid"} {
				data, err := os.ReadFile(f)
				if err == nil {
					_, err = session.SubIDs(data, u.Username, os.Getuid())
				}
				check("subordinate ids in "+f, err)
			}
		}
	}

	if desktop, err := notify.NewDesktop(time.Now); err != nil {
		note("desktop notifications", "unavailable; approvals work through doriath approvals only")
	} else {
		caps, err := desktop.Capabilities()
		_ = desktop.Close()
		switch {
		case err != nil:
			note("desktop notifications", err.Error())
		case !slices.Contains(caps, "actions"):
			note("desktop notifications", "the notification server shows no buttons; decide with doriath approvals")
		default:
			check("desktop notifications with buttons", nil)
		}
	}
	if failed {
		return 1
	}
	return 0
}

func cleanCaches(name string, w io.Writer) error {
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
	fmt.Fprintf(w, "Removed the caches of profile %s.\n", name)
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

func cmdSandboxExec(args []string) error {
	flags := flag.NewFlagSet("sandbox-exec", flag.ContinueOnError)
	var writable stringList
	flags.Var(&writable, "writable", "a path the command may write beneath")
	useLandlock := flags.Bool("landlock", true, "restrict writes to the writable paths")
	seccompFD := flags.Int("seccomp-fd", 0, "a file descriptor with the jail's seccomp program, for a process that joins a running jail")
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
	runtime.LockOSThread()
	if *seccompFD != 0 {
		prog, err := io.ReadAll(os.NewFile(uintptr(*seccompFD), "seccomp"))
		if err != nil {
			return fmt.Errorf("sandbox-exec: read seccomp program: %w", err)
		}
		_ = unix.Close(*seccompFD)
		if err := confine.DropCapabilities(); err != nil {
			return fmt.Errorf("sandbox-exec: %w", err)
		}
		if err := confine.InstallSeccomp(prog); err != nil {
			return fmt.Errorf("sandbox-exec: %w", err)
		}
	}
	if *useLandlock {
		err := landlock.RestrictWrites(writable)
		if errors.Is(err, landlock.ErrUnsupported) {
			return errors.New("sandbox-exec: this kernel has no Landlock; set landlock = false under [hardening] in the profile to run without it")
		}
		if err != nil {
			return fmt.Errorf("sandbox-exec: %w", err)
		}
	}
	return fmt.Errorf("sandbox-exec: exec %s: %w", path, syscall.Exec(path, argv, os.Environ()))
}

const profileTemplate = `description = ""
modules = ["base", "claude"]

[[mounts]]
path = "~/Development/my-project"
mode = "read"
`

func profilesEdit(l *profile.Loader, dir, name string, in io.Reader, w io.Writer) error {
	path := filepath.Join(dir, name+".toml")
	info, err := os.Lstat(path)
	switch {
	case err == nil && info.Mode()&os.ModeSymlink != 0:
		if target, _ := filepath.EvalSymlinks(path); strings.HasPrefix(target, "/nix/store/") {
			return fmt.Errorf("profile %s is managed by home-manager (%s): change it in your nix configuration", name, target)
		}
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(profileTemplate), 0o600); err != nil {
			return err
		}
	case err != nil:
		return err
	}
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	answers := bufio.NewScanner(in)
	for {
		cmd := exec.Command("sh", "-c", editor+` "$1"`, "sh", path)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("editor: %w", err)
		}
		_, err := l.Load(name)
		if err == nil {
			fmt.Fprintf(w, "Profile %s is valid.\n", name)
			return nil
		}
		fmt.Fprintf(w, "Profile %s has a problem:\n  %v\nEdit again? [Y/n] ", name, err)
		if !answers.Scan() || strings.HasPrefix(strings.ToLower(strings.TrimSpace(answers.Text())), "n") {
			return fmt.Errorf("profile %s is not valid", name)
		}
	}
}
