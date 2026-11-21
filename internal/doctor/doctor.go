package doctor

import (
	"context"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/fnune/doriath/internal/bundle"
	"github.com/fnune/doriath/internal/cli"
	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/landlock"
	"github.com/fnune/doriath/internal/notify"
	"github.com/fnune/doriath/internal/oauth"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/seccomp"
	"github.com/fnune/doriath/internal/secret"
	"github.com/fnune/doriath/internal/session"
	"github.com/fnune/doriath/internal/vcstools"
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
	Paths        config.Paths
	Loader       *profile.Loader
	FetchSecrets bool
	Runner       secret.Runner
	Keyring      secret.Keyring
	Logins       secret.Keyring
	Asker        secret.Asker
	Allow        func(*profile.Profile) error
	Dir          string
	Profile      string
	VCS          []vcstools.Tool
}

const fetchTimeout = 2 * time.Minute

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

	out = append(out, checkSecretsOnDisk(p)...)
	secretResults, secrets := checkSecrets(ctx, opts, profiles)
	out = append(out, secretResults...)
	if !opts.FetchSecrets && secrets > 0 {
		note("secrets", "run `doriath doctor --secrets` to fetch each one once")
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

	out = append(out, repository(opts)...)

	if desktop, err := notify.NewDesktop(); err != nil {
		note("desktop notifications", "unavailable; approvals work through `doriath approvals` only")
	} else {
		caps, err := desktop.Capabilities()
		_ = desktop.Close()
		switch {
		case err != nil:
			note("desktop notifications", err.Error())
		case !slices.Contains(caps, "actions"):
			note("desktop notifications", "the notification server shows no buttons; decide with `doriath approvals`")
		default:
			check("desktop notifications with buttons", nil)
		}
	}
	return out
}

func checkSecrets(ctx context.Context, opts Options, profiles []*profile.Profile) ([]Result, int) {
	var out []Result
	check := func(name string, err error) {
		if err != nil {
			out = append(out, Result{Name: name, Level: Problem, Detail: err.Error()})
			return
		}
		out = append(out, Result{Name: name, Level: OK})
	}
	checkSecret := func(name string, b secret.Backend, err error) {
		err = secret.Explained(err)
		if err != nil && !b.Required {
			out = append(out, Result{Name: name, Level: Note, Detail: err.Error() + ": sessions start without it"})
			return
		}
		check(name, err)
	}
	secrets := 0
	for _, prof := range profiles {
		if opts.FetchSecrets && len(prof.Secrets) > 0 {
			if err := opts.Allow(prof); err != nil {
				check("secrets of profile "+prof.Name, err)
				continue
			}
		}
		store := secret.NewConfigured(prof.Secrets, opts.Runner).WithOAuth(oauth.NewTokensOwnedBy(opts.Logins, prof.SecretOwner)).WithKeyring(opts.Keyring, prof.SecretOwner).WithAsker(opts.Asker)
		for _, name := range slices.Sorted(maps.Keys(prof.Secrets)) {
			secrets++
			label := "secret " + prof.Name + "/" + name
			b := prof.Secrets[name]
			switch {
			case opts.FetchSecrets:
				ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
				_, err := store.Get(ctx, name)
				cancel()
				checkSecret(label, b, err)
			case b.OAuth != nil:
				var err error
				if !oauth.SignedIn(opts.Logins, prof.SecretOwner(name), name) {
					err = fmt.Errorf("not signed in: run %s", cli.Code(cli.Line("profiles", "login", prof.Name, name)))
				}
				checkSecret(label+" (oauth)", b, err)
			case b.Keyring:
				checkSecret(label+" (keyring)", b, nil)
			default:
				_, err := exec.LookPath(b.Command[0])
				checkSecret(label+" (command "+b.Command[0]+")", b, err)
			}
		}
	}
	return out, secrets
}

// checkSecretsOnDisk looks only for what earlier versions left behind, so it
// stays cheap: doriath itself keeps no secret on disk.
func checkSecretsOnDisk(p config.Paths) []Result {
	var found []string
	logins := filepath.Join(p.State, "oauth")
	_ = filepath.WalkDir(logins, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		profileName := filepath.Base(filepath.Dir(path))
		found = append(found, fmt.Sprintf("%s holds an OAuth login: run %s to move it into the keyring", path, cli.Code(cli.Line("profiles", "login", profileName))))
		return nil
	})
	if _, err := os.Lstat(p.LegacyWebToken()); err == nil {
		found = append(found, fmt.Sprintf("%s holds the token of the approvals page: run %s, which deletes it", p.LegacyWebToken(), cli.Code(cli.Line("web", "open"))))
	}
	if len(found) == 0 {
		return []Result{{Name: "no secrets on disk", Level: OK}}
	}
	out := make([]Result, len(found))
	for i, detail := range found {
		out[i] = Result{Name: "secret on disk", Level: Problem, Detail: detail}
	}
	return out
}
