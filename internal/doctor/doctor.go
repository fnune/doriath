// Package doctor checks that this machine can run doriath's sessions, for
// the doctor command and the approvals page.
package doctor

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	osuser "os/user"
	"slices"
	"strings"
	"time"

	"github.com/fnune/doriath/internal/bundle"
	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/landlock"
	"github.com/fnune/doriath/internal/notify"
	"github.com/fnune/doriath/internal/oauth"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/seccomp"
	"github.com/fnune/doriath/internal/secret"
	"github.com/fnune/doriath/internal/session"
)

type Level string

const (
	OK      Level = "ok"
	Problem Level = "problem"
	Note    Level = "note"
)

type Result struct {
	Name   string
	Level  Level
	Detail string
}

type Options struct {
	Paths  config.Paths
	Loader *profile.Loader
	// FetchSecrets gets each secret once, which can ask to unlock a password
	// manager. Runner runs the secret commands.
	FetchSecrets bool
	Runner       secret.Runner
}

const fetchTimeout = 2 * time.Minute

// Failed reports whether any result is a problem.
func Failed(results []Result) bool {
	return slices.ContainsFunc(results, func(r Result) bool { return r.Level == Problem })
}

func Run(ctx context.Context, opts Options) []Result {
	var out []Result
	check := func(name string, err error) {
		if err != nil {
			out = append(out, Result{Name: name, Level: Problem, Detail: err.Error()})
			return
		}
		out = append(out, Result{Name: name, Level: OK})
	}
	note := func(name, detail string) { out = append(out, Result{Name: name, Level: Note, Detail: detail}) }
	p := opts.Paths

	_, err := config.LoadUser(p.UserConfig())
	check("config "+p.UserConfig(), err)
	bwrap, err := bundle.Bwrap(p.Bundle(), os.Getenv)
	if bundle.Bundled() {
		check("bundled bubblewrap", err)
	} else {
		check("bubblewrap from the system (development build)", err)
	}
	if err == nil {
		out, runErr := exec.CommandContext(ctx, bwrap, "--unshare-all", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "true").CombinedOutput()
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

	names, err := opts.Loader.Names()
	check("profiles in "+p.Profiles(), err)
	podman := false
	var profiles []*profile.Profile
	for _, n := range names {
		prof, err := opts.Loader.Load(n)
		check("profile "+n, err)
		if err == nil {
			profiles = append(profiles, prof)
			podman = podman || prof.Podman
		}
	}
	if len(names) == 0 {
		note("profiles", "none yet; see https://doriath.fnune.com/install/")
	}

	secrets := 0
	for _, prof := range profiles {
		store := secret.NewConfigured(prof.Secrets, opts.Runner, secret.OSFiles{}).WithOAuth(oauth.NewTokens(p.State, prof.Name))
		for _, name := range slices.Sorted(maps.Keys(prof.Secrets)) {
			secrets++
			label := "secret " + prof.Name + "/" + name
			b := prof.Secrets[name]
			switch {
			case opts.FetchSecrets:
				ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
				_, err := store.Get(ctx, name)
				cancel()
				check(label, err)
			case b.OAuth != nil:
				_, err := os.Stat(oauth.StatePath(p.State, prof.Name, name))
				if errors.Is(err, os.ErrNotExist) {
					err = fmt.Errorf("not signed in: run doriath profiles login %s %s", prof.Name, name)
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
	if !opts.FetchSecrets && secrets > 0 {
		note("secrets", "run doriath doctor --secrets to fetch each one once")
	}

	if podman {
		for _, tool := range []string{"unshare", "nsenter", "podman", "newuidmap"} {
			if _, err := exec.LookPath(tool); err != nil {
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
	return out
}
