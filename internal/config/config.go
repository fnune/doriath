package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
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

func (p Paths) AllowedProfiles() string { return filepath.Join(p.State, "profiles") }

func (p Paths) Moved(session string) string { return filepath.Join(p.State, "moved", session) }

func (p Paths) Bundle() string { return filepath.Join(p.Cache, "bundle") }

func (p Paths) Backups() string { return filepath.Join(p.State, "backups") }

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

type User struct {
	Approvals Approvals
	Desktop   Desktop
	Terminal  Terminal
}

type Desktop struct {
	Notifications bool
	Tray          bool
}

type Terminal struct {
	Title bool
	Bar   bool
	// Env is set on bubblewrap, the process your terminal sees in place of
	// the agent. The jail does not get it.
	Env map[string]string
}

type Approvals struct {
	// HostWait is how long a request doriath refused waits for your
	// decision before the agent gets an error. Nil means the default.
	HostWait *time.Duration
	ToolWait time.Duration
}

func (u User) DefaultHostWait() time.Duration {
	switch {
	case u.Approvals.HostWait != nil:
		return *u.Approvals.HostWait
	case u.Desktop.Notifications:
		return 2 * time.Minute
	}
	return 0
}

type userFile struct {
	Approvals struct {
		HostWait *string `toml:"host_wait"`
		ToolWait *string `toml:"tool_wait"`
	} `toml:"approvals"`
	Desktop struct {
		Notifications *bool `toml:"notifications"`
		Tray          *bool `toml:"tray"`
	} `toml:"desktop"`
	Terminal struct {
		Title *bool             `toml:"title"`
		Bar   *bool             `toml:"bar"`
		Env   map[string]string `toml:"env"`
	} `toml:"terminal"`
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func LoadUser(path string) (User, error) {
	u := User{
		Approvals: Approvals{ToolWait: time.Minute},
		Desktop:   Desktop{Notifications: true, Tray: true},
		Terminal:  Terminal{Title: true, Bar: true},
	}
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
	if md.IsDefined("approvals", "desktop") {
		return User{}, fmt.Errorf("%s: approvals.desktop is now desktop.notifications", path)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return User{}, fmt.Errorf("%s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	if f.Desktop.Notifications != nil {
		u.Desktop.Notifications = *f.Desktop.Notifications
	}
	if f.Desktop.Tray != nil {
		u.Desktop.Tray = *f.Desktop.Tray
	}
	if f.Terminal.Title != nil {
		u.Terminal.Title = *f.Terminal.Title
	}
	if f.Terminal.Bar != nil {
		u.Terminal.Bar = *f.Terminal.Bar
	}
	for k := range f.Terminal.Env {
		if !envName.MatchString(k) {
			return User{}, fmt.Errorf("%s: terminal.env %q: want a variable name, such as HERDR_AGENT", path, k)
		}
	}
	u.Terminal.Env = f.Terminal.Env
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
