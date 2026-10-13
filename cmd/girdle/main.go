// Command girdle runs coding agents in a jail that shows them only what
// their profile names. main.go is the composition root: it is the only place
// that picks concrete implementations.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/fnune/girdle/internal/approval"
	"github.com/fnune/girdle/internal/bundle"
	"github.com/fnune/girdle/internal/config"
	"github.com/fnune/girdle/internal/modules"
	"github.com/fnune/girdle/internal/notify"
	"github.com/fnune/girdle/internal/profile"
	"github.com/fnune/girdle/internal/secret"
	"github.com/fnune/girdle/internal/session"
)

var version = "dev"

const usage = `girdle runs a coding agent in a jail that shows it only what its profile names.

Usage:
  girdle run [--profile NAME] [--] COMMAND [ARGS...]
  girdle approvals [list]
  girdle approvals allow ID [--for once|session|DURATION]
  girdle approvals deny ID [--reason TEXT]
  girdle approvals watch
  girdle sessions
  girdle clean PROFILE
  girdle profiles [list | show NAME]
  girdle doctor
  girdle version

Inside a jail:
  girdle init [--forward PORT=SOCKET]... -- COMMAND [ARGS...]
  girdle hook claude permission-request|notification
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	var err error
	code := 0
	switch args[0] {
	case "run":
		code, err = cmdRun(args[1:])
	case "init":
		code, err = cmdInit(args[1:])
	case "hook":
		err = cmdHook(args[1:], os.Stdin, os.Stdout)
	case "approvals":
		err = cmdApprovals(args[1:])
	case "sessions":
		err = cmdSessions()
	case "clean":
		err = cmdClean(args[1:])
	case "profiles":
		err = cmdProfiles(args[1:])
	case "doctor":
		code = cmdDoctor()
	case "version", "--version":
		fmt.Println("girdle", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "girdle: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "girdle:", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

func paths() (config.Paths, error) { return config.DefaultPaths(os.Getenv) }

func loader(p config.Paths) *profile.Loader {
	return &profile.Loader{
		Profiles: os.DirFS(p.Profiles()),
		Modules:  []fs.FS{os.DirFS(p.Modules()), modules.FS},
		Home:     p.Home,
	}
}

func cmdRun(args []string) (int, error) {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	name := flags.String("profile", "", "profile to use (default: the one whose match paths contain the working directory)")
	if err := flags.Parse(args); err != nil {
		return 2, err
	}
	command := flags.Args()
	if len(command) == 0 {
		return 2, errors.New("run: name the command to run, for example: girdle run -- claude")
	}
	p, err := paths()
	if err != nil {
		return 1, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return 1, err
	}
	l := loader(p)
	var prof *profile.Profile
	if *name != "" {
		prof, err = l.Load(*name)
	} else {
		prof, err = l.Find(cwd)
	}
	if err != nil {
		return 1, err
	}
	user, err := config.LoadUser(p.UserConfig(), p.Home)
	if err != nil {
		return 1, err
	}
	bwrap, err := bundle.Bwrap(p.Bundle(), os.Getenv)
	if err != nil {
		return 1, err
	}
	exe, err := os.Executable()
	if err != nil {
		return 1, fmt.Errorf("find girdle's own binary: %w", err)
	}

	clock := realClock{}
	var notifier approval.Notifier = notify.None{}
	var informer session.Informer = notify.None{}
	if user.Approvals.Desktop {
		desktop, err := notify.NewDesktop(opener{}, time.Now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "girdle: desktop notifications are off (%v); use girdle approvals\n", err)
		} else {
			defer func() { _ = desktop.Close() }()
			notifier, informer = desktop, desktop
		}
	}
	gitDesktop, _ := exec.Command("git", "config", "--global", "--includes", "--list", "-z").Output()

	deps := session.Deps{
		Paths:      p,
		User:       user,
		Secrets:    secret.NewConfigured(user.Secrets, execRunner{}, secret.OSFiles{}),
		Notifier:   notifier,
		Informer:   informer,
		Clock:      clock,
		Dialer:     &net.Dialer{Timeout: 30 * time.Second},
		Getenv:     os.Getenv,
		Environ:    os.Environ(),
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		Bwrap:      bwrap,
		Exe:        exe,
		GitDesktop: gitDesktop,
		Unshare:    lookPath("unshare"),
		Nsenter:    lookPath("nsenter"),
		Podman:     lookPath("podman"),
	}
	s, err := session.New(deps, session.Request{Profile: prof, Cwd: cwd, Command: command})
	if err != nil {
		return 1, err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	return s.Run(ctx)
}

func lookPath(name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return p
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

type execRunner struct{}

func (execRunner) Output(ctx context.Context, argv []string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var stderr limitedBuffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	return out, stderr.b, err
}

type limitedBuffer struct{ b []byte }

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := 4096 - len(l.b); room > 0 {
		l.b = append(l.b, p[:min(len(p), room)]...)
	}
	return len(p), nil
}

type opener struct{}

func (opener) Open(url string) error {
	cmd := exec.Command("xdg-open", url)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return cmd.Start()
}
