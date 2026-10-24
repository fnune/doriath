// Package config locates doriath's directories and reads the user config,
// which holds what is personal to one person: where their secrets live and
// how they want to be asked for approvals.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

const appName = "doriath"

type Paths struct {
	Home    string
	Config  string
	State   string
	Cache   string
	Runtime string
}

func (p Paths) Profiles() string   { return filepath.Join(p.Config, "profiles") }
func (p Paths) Modules() string    { return filepath.Join(p.Config, "modules") }
func (p Paths) UserConfig() string { return filepath.Join(p.Config, "config.toml") }
func (p Paths) AuditLog() string   { return filepath.Join(p.State, "audit.jsonl") }
func (p Paths) WebToken() string   { return filepath.Join(p.State, "web-token") }
func (p Paths) WebAddr() string    { return filepath.Join(p.Runtime, "web-addr") }
func (p Paths) Sessions() string   { return filepath.Join(p.Runtime, "sessions") }

// Private lists doriath's own configuration, state and cache. They move
// with the XDG variables, so they are here and not in the private-paths
// module, which refuses your keys and logins.
func (p Paths) Private() []string {
	return []string{p.Config, p.State, p.Cache}
}

// ImagePins holds the digests a profile's container image tags resolved to.
// It is state rather than cache: deleting it trusts the next pull again.
func (p Paths) ImagePins(profile string) string {
	return filepath.Join(p.State, "images", profile+".json")
}

// AgentCache is where a profile's caches live. Nothing outside the jail reads
// these, so what an agent writes there cannot reach the desktop's tools.
func (p Paths) AgentCache(profile string) string {
	return filepath.Join(p.Cache, "agents", profile)
}

// AllowedProfiles holds the grants of each profile you allowed. It is
// state: deleting it asks again for every profile.
func (p Paths) AllowedProfiles() string { return filepath.Join(p.State, "profiles") }

func (p Paths) Bundle() string { return filepath.Join(p.Cache, "bundle") }

// Backups holds, per session, the record of the branches it started with and
// the objects that keep them alive. It is state: doriath restore reads it
// after the session ends.
func (p Paths) Backups() string { return filepath.Join(p.State, "backups") }

// DefaultPaths follows the XDG base directory specification. DORIATH_CONFIG_DIR
// overrides the config directory, for example to point at a generated one.
func DefaultPaths(getenv func(string) string) (Paths, error) {
	home := getenv("HOME")
	if home == "" || !filepath.IsAbs(home) {
		return Paths{}, errors.New("HOME must be set to an absolute path")
	}
	xdg := func(name, fallback string) string {
		if v := getenv(name); filepath.IsAbs(v) {
			return filepath.Join(v, appName)
		}
		return filepath.Join(home, fallback, appName)
	}
	p := Paths{
		Home:   home,
		Config: xdg("XDG_CONFIG_HOME", ".config"),
		State:  xdg("XDG_STATE_HOME", ".local/state"),
		Cache:  xdg("XDG_CACHE_HOME", ".cache"),
	}
	if dir := getenv("DORIATH_CONFIG_DIR"); dir != "" {
		if !filepath.IsAbs(dir) {
			return Paths{}, fmt.Errorf("DORIATH_CONFIG_DIR %q must be absolute", dir)
		}
		p.Config = dir
	}
	runtime := getenv("XDG_RUNTIME_DIR")
	if !filepath.IsAbs(runtime) {
		return Paths{}, errors.New("XDG_RUNTIME_DIR must be set: doriath keeps its sockets there")
	}
	p.Runtime = filepath.Join(runtime, appName)
	return p, nil
}

// User is doriath's own configuration, which holds for every profile.
// Secrets belong to the profiles that use them.
type User struct {
	Approvals Approvals
	Terminal  Terminal
}

type Terminal struct {
	// Title names the session's profile in the terminal's window title
	// while a session runs.
	Title bool
	// Bar shows the session on the terminal's last row, below the agent.
	// Without it, the agent gets your terminal as it is.
	Bar bool
}

type Approvals struct {
	Desktop bool
	// HostWait is how long a request doriath refused waits for your
	// decision before the agent gets an error. Nil means the default.
	HostWait *time.Duration
	// ToolWait is how long an agent's permission prompt waits in doriath's
	// queue before the agent shows its own.
	ToolWait time.Duration
}

// DefaultHostWait holds requests while desktop notifications can show them,
// and not at all without them, where nobody sees the request in time.
func (a Approvals) DefaultHostWait() time.Duration {
	switch {
	case a.HostWait != nil:
		return *a.HostWait
	case a.Desktop:
		return 2 * time.Minute
	}
	return 0
}

type userFile struct {
	Approvals struct {
		Desktop  *bool   `toml:"desktop"`
		HostWait *string `toml:"host_wait"`
		ToolWait *string `toml:"tool_wait"`
	} `toml:"approvals"`
	Terminal struct {
		Title *bool `toml:"title"`
		Bar   *bool `toml:"bar"`
	} `toml:"terminal"`
}

// LoadUser reads config.toml. A missing file is an empty configuration.
func LoadUser(path string) (User, error) {
	u := User{Approvals: Approvals{Desktop: true, ToolWait: time.Minute}, Terminal: Terminal{Title: true, Bar: true}}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return u, nil
	}
	if err != nil {
		return User{}, fmt.Errorf("read %s: %w", path, err)
	}
	var f userFile
	md, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&f)
	if err != nil {
		return User{}, fmt.Errorf("%s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return User{}, fmt.Errorf("%s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	if f.Approvals.Desktop != nil {
		u.Approvals.Desktop = *f.Approvals.Desktop
	}
	if f.Terminal.Title != nil {
		u.Terminal.Title = *f.Terminal.Title
	}
	if f.Terminal.Bar != nil {
		u.Terminal.Bar = *f.Terminal.Bar
	}
	if f.Approvals.HostWait != nil {
		d, err := time.ParseDuration(*f.Approvals.HostWait)
		if err != nil || d < 0 || d > time.Hour {
			return User{}, fmt.Errorf("%s: approvals.host_wait %q: want a duration from 0s to 1h, such as 2m", path, *f.Approvals.HostWait)
		}
		u.Approvals.HostWait = &d
	}
	if f.Approvals.ToolWait != nil {
		d, err := time.ParseDuration(*f.Approvals.ToolWait)
		if err != nil || d <= 0 || d > time.Hour {
			return User{}, fmt.Errorf("%s: approvals.tool_wait %q: want a duration from 1s to 1h, such as 90s", path, *f.Approvals.ToolWait)
		}
		u.Approvals.ToolWait = d
	}
	return u, nil
}
