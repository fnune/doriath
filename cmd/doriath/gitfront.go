package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/control"
	"github.com/fnune/doriath/internal/session"
)

// cmdGitFront runs in the jail as git, for the agent and for jj. The jail
// keeps .git/config read-only, so that the agent cannot make git on your
// machine run what it names, and git cannot write the harmless settings it
// records on its own: the upstream of a branch, or a remote that you allow.
// The front runs your git and then asks doriath to write those, under the
// same rules as doriath request edit. Commands that write no config run as
// they are.
func cmdGitFront(args []string) int {
	git, err := realGit()
	if err != nil {
		fmt.Fprintln(os.Stderr, "doriath:", err)
		return 1
	}
	args = absoluteWorktrees(args)
	broker := os.Getenv("DORIATH_BROKER")
	inv := parseGit(args)
	if broker == "" || !slices.Contains([]string{"push", "branch", "checkout", "switch", "remote"}, inv.command) {
		err := syscall.Exec(git, append([]string{"git"}, args...), os.Environ())
		fmt.Fprintln(os.Stderr, "doriath:", err)
		return 1
	}
	var out, errOut bytes.Buffer
	cmd := exec.Command(git, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = io.MultiWriter(os.Stdout, &out)
	cmd.Stderr = io.MultiWriter(os.Stderr, &errOut)
	code := exitCode(cmd.Run())
	config := failedConfig(errOut.String(), inv.dir)
	if config == "" {
		return code
	}
	g := hostGit{bin: git, dir: inv.dir}
	settings, reason := g.intended(inv, out.String()+errOut.String())
	if len(settings) == 0 {
		return code
	}
	if err := recordConfig(context.Background(), broker, git, config, settings, reason); err != nil {
		fmt.Fprintln(os.Stderr, "doriath:", err)
		return code
	}
	if inv.command == "remote" {
		return 0
	}
	return code
}

// absoluteWorktrees asks git for absolute worktree paths where jj asks for
// relative ones: those need an extension in .git/config, which the jail
// cannot write and nix refuses to read. The jail sees each repository where
// you do, so absolute paths serve both.
func absoluteWorktrees(args []string) []string {
	out := slices.Clone(args)
	for i := 1; i < len(out); i++ {
		if out[i-1] == "-c" && strings.EqualFold(out[i], "worktree.useRelativePaths=true") {
			out[i] = "worktree.useRelativePaths=false"
		}
	}
	return out
}

// realGit finds git on PATH, past the front itself.
func realGit() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(self); err == nil {
		self = real
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		p := filepath.Join(dir, "git")
		real, err := filepath.EvalSymlinks(p)
		if err != nil || real == self {
			continue
		}
		if info, err := os.Stat(real); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", errors.New("git is not on PATH")
}

func exitCode(err error) int {
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.ExitCode()
	}
	fmt.Fprintln(os.Stderr, "doriath:", err)
	return 1
}

// invocation is a git command line: the directory it runs in, after -C,
// and the subcommand with its arguments.
type invocation struct {
	dir     string
	command string
	args    []string
}

func parseGit(args []string) invocation {
	inv := invocation{dir: "."}
	if wd, err := os.Getwd(); err == nil {
		inv.dir = wd
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-C" && i+1 < len(args):
			i++
			if filepath.IsAbs(args[i]) {
				inv.dir = args[i]
			} else {
				inv.dir = filepath.Join(inv.dir, args[i])
			}
		case (a == "-c" || a == "--git-dir" || a == "--work-tree" || a == "--namespace") && i+1 < len(args):
			i++
		case strings.HasPrefix(a, "-"):
		default:
			inv.command, inv.args = a, args[i+1:]
			return inv
		}
	}
	return inv
}

var configFailure = regexp.MustCompile(`(?m)^error: could not (?:write|lock) config file (.+?): `)

// failedConfig is the config file that git could not write, if any.
func failedConfig(stderr, dir string) string {
	m := configFailure.FindStringSubmatch(stderr)
	if m == nil {
		return ""
	}
	if filepath.IsAbs(m[1]) {
		return m[1]
	}
	return filepath.Join(dir, m[1])
}

type setting struct{ key, value string }

type hostGit struct{ bin, dir string }

func (g hostGit) output(args ...string) string {
	cmd := exec.Command(g.bin, append([]string{"-C", g.dir}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (g hostGit) remotes() []string { return strings.Fields(g.output("remote")) }

func (g hostGit) currentBranch() string {
	return g.output("symbolic-ref", "--quiet", "--short", "HEAD")
}

// intended is what git meant to write: the upstreams it reports or that its
// arguments name, or the remote that git remote add adds.
func (g hostGit) intended(inv invocation, output string) ([]setting, string) {
	if inv.command == "remote" {
		if s := remoteAdd(inv.args); s != nil {
			return s, "git remote add, which the jail cannot write into .git/config"
		}
		return nil, ""
	}
	upstreams := map[string]string{}
	for _, m := range trackMessage.FindAllStringSubmatch(output, -1) {
		upstreams[m[1]] = m[2]
	}
	switch inv.command {
	case "push":
		maps.Copy(upstreams, g.pushUpstreams(inv.args))
	case "branch":
		maps.Copy(upstreams, g.setUpstreamTo(inv.args))
	}
	remotes := g.remotes()
	var out []setting
	for _, branch := range slices.Sorted(maps.Keys(upstreams)) {
		remote, ref := splitUpstream(upstreams[branch], remotes)
		out = append(out, setting{"branch." + branch + ".remote", remote}, setting{"branch." + branch + ".merge", "refs/heads/" + ref})
	}
	return out, "the upstream git records for a branch, which the jail cannot write into .git/config"
}

var trackMessage = regexp.MustCompile(`(?m)^branch '([^']+)' set up to track '([^']+)'`)

// splitUpstream splits origin/main into its remote and branch. An upstream
// that names no remote is a local branch, which git records as remote ".".
func splitUpstream(upstream string, remotes []string) (string, string) {
	best := ""
	for _, r := range remotes {
		if strings.HasPrefix(upstream, r+"/") && len(r) > len(best) {
			best = r
		}
	}
	if best == "" {
		return ".", upstream
	}
	return best, strings.TrimPrefix(upstream, best+"/")
}

// pushUpstreams reads git push [-u] [remote [refspec...]] as git does: an
// upstream for each pushed branch, with -u or with push.autoSetupRemote.
func (g hostGit) pushUpstreams(args []string) map[string]string {
	setUpstream := false
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			positional = append(positional, args[i+1:]...)
			i = len(args)
		case a == "-u" || a == "--set-upstream":
			setUpstream = true
		case a == "--repo" || a == "--receive-pack" || a == "--exec" || a == "-o" || a == "--push-option":
			i++
		case strings.HasPrefix(a, "--"):
		case strings.HasPrefix(a, "-") && len(a) > 1:
			setUpstream = setUpstream || strings.Contains(a[1:], "u")
		default:
			positional = append(positional, a)
		}
	}
	current := g.currentBranch()
	if !setUpstream {
		if len(positional) > 1 || current == "" || g.output("config", "--bool", "push.autoSetupRemote") != "true" || g.output("config", "branch."+current+".merge") != "" {
			return nil
		}
	}
	remote := ""
	if len(positional) > 0 {
		remote, positional = positional[0], positional[1:]
	} else {
		for _, key := range []string{"branch." + current + ".pushRemote", "remote.pushDefault", "branch." + current + ".remote"} {
			if remote = g.output("config", key); remote != "" {
				break
			}
		}
		if remote == "" {
			remote = "origin"
		}
	}
	if len(positional) == 0 && current != "" {
		positional = []string{current}
	}
	out := map[string]string{}
	for _, spec := range positional {
		src, dst, _ := strings.Cut(strings.TrimPrefix(spec, "+"), ":")
		if src == "HEAD" {
			src = current
		}
		if dst == "" {
			dst = src
		}
		src, dst = strings.TrimPrefix(src, "refs/heads/"), strings.TrimPrefix(dst, "refs/heads/")
		if src == "" || g.output("rev-parse", "--verify", "--quiet", "refs/heads/"+src) == "" {
			continue
		}
		out[src] = remote + "/" + dst
	}
	return out
}

// setUpstreamTo reads git branch --set-upstream-to=UP [BRANCH] and -u UP.
func (g hostGit) setUpstreamTo(args []string) map[string]string {
	upstream := ""
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "--set-upstream-to="):
			upstream = strings.TrimPrefix(a, "--set-upstream-to=")
		case (a == "--set-upstream-to" || a == "-u") && i+1 < len(args):
			i++
			upstream = args[i]
		case strings.HasPrefix(a, "-"):
		default:
			positional = append(positional, a)
		}
	}
	if upstream == "" {
		return nil
	}
	branch := g.currentBranch()
	if len(positional) > 0 {
		branch = positional[0]
	}
	if branch == "" {
		return nil
	}
	return map[string]string{branch: upstream}
}

// remoteAdd reads git remote add NAME URL. Options that change what the
// remote fetches stay with git: the front adds only a plain remote.
func remoteAdd(args []string) []setting {
	if len(args) != 3 || args[0] != "add" || strings.HasPrefix(args[1], "-") || strings.HasPrefix(args[2], "-") {
		return nil
	}
	name, url := args[1], args[2]
	return []setting{
		{"remote." + name + ".url", url},
		{"remote." + name + ".fetch", "+refs/heads/*:refs/remotes/" + name + "/*"},
	}
}

// recordConfig writes settings into a copy of config with git, and asks
// doriath to make the file so.
func recordConfig(ctx context.Context, broker, git, config string, settings []setting, reason string) error {
	current, err := os.ReadFile(config)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp("", "doriath-gitconfig-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(current); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	for _, s := range settings {
		if out, err := exec.Command(git, "config", "--file", tmp.Name(), s.key, s.value).CombinedOutput(); err != nil {
			return fmt.Errorf("git config %s: %w: %s", s.key, err, strings.TrimSpace(string(out)))
		}
	}
	content, err := os.ReadFile(tmp.Name())
	if err != nil {
		return err
	}
	var res session.RequestEditResult
	if err := control.Call(ctx, broker, session.MethodRequestEdit, session.RequestEditParams{Path: config, Content: string(content), Reason: reason}, &res); err != nil {
		return err
	}
	switch {
	case res.Pending != "":
		return fmt.Errorf("asked you to write %s into %s; once you answer, run: doriath request wait %s, then the git command again", describe(settings), config, res.Pending)
	case res.Decision.Verdict == approval.VerdictAllow:
		return nil
	case res.Decision.Verdict == approval.VerdictDeny:
		return fmt.Errorf("you refused to write %s into %s", describe(settings), config)
	}
	return fmt.Errorf("nobody decided whether to write %s into %s", describe(settings), config)
}

func describe(settings []setting) string {
	var b strings.Builder
	for i, s := range settings {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s = %s", s.key, s.value)
	}
	return b.String()
}
