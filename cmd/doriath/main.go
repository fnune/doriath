// Command doriath runs coding agents in a jail that shows them only what
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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fnune/doriath/internal/allowed"
	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/bundle"
	"github.com/fnune/doriath/internal/clipboard"
	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/modules"
	"github.com/fnune/doriath/internal/notify"
	"github.com/fnune/doriath/internal/oauth"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/promote"
	"github.com/fnune/doriath/internal/secret"
	"github.com/fnune/doriath/internal/session"
	"github.com/fnune/doriath/internal/term"
	"github.com/fnune/doriath/internal/vcstools"
	gittool "github.com/fnune/doriath/internal/vcstools/git"
	jjtool "github.com/fnune/doriath/internal/vcstools/jj"
	"golang.org/x/sys/unix"
)

var version = "dev"

const usage = `doriath runs a coding agent in a jail that shows it only what its profile names.

Sessions:
  doriath run --profile NAME [--current DIR] [--learn] [--] COMMAND [ARGS...]
  doriath exec [--session ID] [--] [COMMAND [ARGS...]]
  doriath forward [--session ID] PORT[:JAIL_PORT]
  doriath status [--session ID]
  doriath log [--session ID] [--profile NAME] [--denied] [--since 1h] [--json] [--follow]

Answers:
  doriath approvals [list]
  doriath approvals allow ID [--for once|session|DURATION]
  doriath approvals deny ID [--reason TEXT]
  doriath approvals grant PATH [--session ID]
  doriath web [--listen HOST:PORT]
  doriath web open [--listen HOST:PORT] [--print]

Configuration:
  doriath profiles [list | show NAME [--json] | edit NAME | allow NAME [--current DIR] | login NAME [SECRET] | clean NAME]
  doriath modules [list | show NAME [--path]]

Repositories:
  doriath clean
  doriath restore SESSION [BRANCH...]

Setup:
  doriath doctor [--secrets] [--profile NAME]
  doriath direnv
  doriath completion zsh
  doriath version

Inside a jail:
  doriath status
  doriath request write PATH [--reason TEXT]
  doriath request wait ID|HOST|PATH
`

func main() {
	if name := filepath.Base(os.Args[0]); name == session.JJGit || name == "git" {
		os.Exit(cmdGitFront(os.Args[1:]))
	}
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	ctx := context.Background()
	var err error
	code := 0
	switch args[0] {
	case "run":
		code, err = cmdRun(args[1:])
	case "exec":
		code, err = cmdExec(args[1:])
	case "forward":
		err = cmdForward(args[1:])
	case "__relay":
		err = cmdRelay(args[1:])
	case "__init":
		code, err = cmdInit(args[1:])
	case "__sandbox-exec":
		err = cmdSandboxExec(args[1:])
	case "__hook":
		err = cmdHook(args[1:], os.Stdin, os.Stdout)
	case "approvals":
		err = cmdApprovals(ctx, args[1:], realClock{}, os.Stdout)
	case "web":
		err = cmdWeb(ctx, args[1:], realClock{}, os.Stdout)
	case "clean":
		err = cmdClean(args[1:], os.Stdin, os.Stdout)
	case "restore":
		err = cmdRestore(args[1:], os.Stdout)
	case "request":
		err = cmdRequest(args[1:], os.Stdout)
	case "__agent-command":
		err = cmdAgentCommand(args[1:], os.Stdout)
	case "direnv":
		err = cmdDirenv(os.Stdout)
	case "__promote":
		err = promote.Inner(args[1:])
	case "status":
		err = cmdStatus(args[1:], os.Stdout)
	case "__ssh":
		code, err = cmdSSH(args[1:])
	case "__statusline":
		err = cmdStatusline(os.Stdout)
	case "log":
		err = cmdLog(ctx, args[1:], realClock{}, os.Stdout)
	case "completion":
		err = cmdCompletion(args[1:], os.Stdout)
	case "__complete":
		cmdComplete(args[1:], os.Stdout)
	case "modules":
		err = cmdModulesFromArgs(args[1:], os.Stdout)
	case "profiles":
		err = cmdProfiles(args[1:], os.Stdin, os.Stdout)
	case "doctor":
		code = cmdDoctor(args[1:], os.Stdout)
	case "version", "--version":
		fmt.Println("doriath", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "doriath: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if err != nil {
		term.New(os.Stderr).Problem(err.Error())
		if code == 0 {
			code = 1
		}
	}
	return code
}

func paths() (config.Paths, error) { return config.DefaultPaths(os.Getenv) }

func loader(p config.Paths, dir string) *profile.Loader {
	root, profiles := repositoryProfiles(dir)
	return &profile.Loader{
		Profiles:       os.DirFS(p.Profiles()),
		Modules:        []fs.FS{os.DirFS(p.Modules()), modules.FS},
		Repository:     profiles,
		RepositoryRoot: root,
		Home:           p.Home,
	}
}

func workingDir() string {
	dir, _ := os.Getwd()
	return dir
}

func repositoryProfiles(dir string) (string, fs.FS) {
	if dir == "" {
		return "", nil
	}
	repo := profile.FindRepository(dir, func(p string) bool { return osKind(p) != "" })
	if repo == "" {
		return "", nil
	}
	root, err := os.OpenRoot(filepath.Join(repo, profile.RepoProfiles))
	if err != nil {
		return repo, nil
	}
	return repo, root.FS()
}

func cmdRun(args []string) (int, error) {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	name := flags.String("profile", "", "the profile to use (required)")
	current := flags.String("current", "", "the directory the session is for, as {current}, instead of the working directory")
	learn := flags.Bool("learn", false, "let egress reach any public host, and list the hosts the profile does not allow when the session ends")
	if err := flags.Parse(args); err != nil {
		return 2, err
	}
	command := flags.Args()
	if len(command) == 0 {
		return 2, errors.New("run: name the command to run, for example: doriath run -- claude")
	}
	if err := refuseRoot(os.Geteuid()); err != nil {
		return 1, err
	}
	p, err := paths()
	if err != nil {
		return 1, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return 1, err
	}
	start, cwd, err := startDirs(*current, cwd)
	if err != nil {
		return 2, err
	}
	if *name == "" {
		return 2, errors.New("run: name the profile, for example: doriath run --profile my-app -- claude")
	}
	prof, err := loader(p, start).Load(*name)
	if err != nil {
		return 1, err
	}
	if err := confirmProfile(allowed.NewStore(p.AllowedProfiles()), prof, allowedKey(prof, start), os.Stdin, os.Stderr, isTerminal(os.Stdin)); err != nil {
		return 1, err
	}
	user, err := config.LoadUser(p.UserConfig())
	if err != nil {
		return 1, err
	}
	bwrap, err := bundle.Bwrap(p.Bundle(), os.Getenv)
	if err != nil {
		return 1, err
	}
	exe, err := os.Executable()
	if err != nil {
		return 1, fmt.Errorf("find doriath's own binary: %w", err)
	}

	clock := realClock{}
	var notifier approval.Notifier = notify.None{}
	var informer session.Informer = notify.None{}
	if user.Approvals.Desktop {
		desktop, err := notify.NewDesktop(time.Now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "doriath: desktop notifications are off (%v); use doriath approvals\n", err)
		} else {
			defer func() { _ = desktop.Close() }()
			desktop.Page = webPage{paths: p}
			notifier, informer = desktop, desktop
		}
	}
	tools := vcsJailTools(p)

	deps := session.Deps{
		Paths:       p,
		User:        user,
		Secrets:     secret.NewConfigured(prof.Secrets, execRunner{}, secret.OSFiles{}).WithOAuth(oauth.NewTokensOwnedBy(p.State, prof.SecretOwner)),
		Notifier:    notifier,
		Informer:    informer,
		Clock:       clock,
		Dialer:      &net.Dialer{Timeout: 30 * time.Second},
		Resolver:    net.DefaultResolver,
		LocalDialer: &net.Dialer{Timeout: 10 * time.Second},
		Getenv:      os.Getenv,
		Environ:     os.Environ(),
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		Bwrap:       bwrap,
		Exe:         exe,
		VCS:         tools,
		Unshare:     lookPath("unshare"),
		Nsenter:     lookPath("nsenter"),
		Podman:      lookPath("podman"),
		Git:         lookPath("git"),
		JJ:          lookPath("jj"),
		HostWait:    hostWait(user.Approvals, notifier),
		SystemdRun:  lookPath("systemd-run"),
		Promote:     promote.Writable,
		Clipboard:   hostClipboard(os.Getenv, lookPath("wl-paste")),
	}
	finishInterrupted(p, deps.Stderr)
	s, err := session.New(deps, session.Request{Profile: prof, Cwd: cwd, Current: start, Command: command, Learn: *learn})
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

// hostClipboard reads your Wayland clipboard, or returns nil outside a
// Wayland session.
func hostClipboard(getenv func(string) string, wlPaste string) clipboard.Source {
	display := getenv("WAYLAND_DISPLAY")
	if display == "" || wlPaste == "" {
		return nil
	}
	return clipboard.WlPaste{Bin: wlPaste, Env: []string{"WAYLAND_DISPLAY=" + display, "XDG_RUNTIME_DIR=" + getenv("XDG_RUNTIME_DIR")}}
}

type clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

type execRunner struct{}

func (execRunner) Output(ctx context.Context, argv []string, terminal bool) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var stderr limitedBuffer
	cmd.Stderr = &stderr
	if terminal && isTerminal(os.Stdin) {
		cmd.Stdin = os.Stdin
		cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
	}
	out, err := cmd.Output()
	return out, stderr.b, err
}

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
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

func refuseRoot(euid int) error {
	if euid == 0 {
		return errors.New("run: doriath does not run as root: the files the agent writes and the podman service would belong to root. Run it as your own user")
	}
	return nil
}

func startDirs(current, cwd string) (string, string, error) {
	if current == "" {
		return cwd, cwd, nil
	}
	abs, err := filepath.Abs(current)
	if err != nil {
		return "", "", err
	}
	if info, err := os.Stat(abs); err != nil || !info.IsDir() {
		return "", "", fmt.Errorf("run: --current %s is not a directory", current)
	}
	if rel, err := filepath.Rel(abs, cwd); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
		return abs, cwd, nil
	}
	return abs, abs, nil
}

func hostWait(a config.Approvals, n approval.Notifier) time.Duration {
	if _, none := n.(notify.None); none && a.HostWait == nil {
		return 0
	}
	return a.DefaultHostWait()
}

func vcsJailTools(p config.Paths) []vcstools.Tool {
	gitDesktop, _ := exec.Command("git", "config", "--global", "--includes", "--list", "-z").Output()
	files := gittool.HostFiles(gitDesktop, p.Home, os.Getenv, os.ReadFile)
	return []vcstools.Tool{gittool.New(gitDesktop, files), jjtool.New(p.Home, osKind)}
}

func osKind(p string) string {
	info, err := os.Stat(p)
	switch {
	case err != nil:
		return ""
	case info.IsDir():
		return "dir"
	}
	return "file"
}
