// Package config locates girdle's directories and reads the user config,
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
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/fnune/girdle/internal/secret"
)

const appName = "girdle"

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
func (p Paths) Sessions() string   { return filepath.Join(p.Runtime, "sessions") }

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

func (p Paths) Bundle() string { return filepath.Join(p.Cache, "bundle") }

// DefaultPaths follows the XDG base directory specification. GIRDLE_CONFIG_DIR
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
	if dir := getenv("GIRDLE_CONFIG_DIR"); dir != "" {
		if !filepath.IsAbs(dir) {
			return Paths{}, fmt.Errorf("GIRDLE_CONFIG_DIR %q must be absolute", dir)
		}
		p.Config = dir
	}
	runtime := getenv("XDG_RUNTIME_DIR")
	if !filepath.IsAbs(runtime) {
		return Paths{}, errors.New("XDG_RUNTIME_DIR must be set: girdle keeps its sockets there")
	}
	p.Runtime = filepath.Join(runtime, appName)
	return p, nil
}

type User struct {
	Secrets   map[string]secret.Backend
	Approvals Approvals
}

type Approvals struct {
	Desktop bool
}

type userFile struct {
	Secrets   map[string]secretFile `toml:"secrets"`
	Approvals struct {
		Desktop *bool `toml:"desktop"`
	} `toml:"approvals"`
}

type secretFile struct {
	File    string   `toml:"file"`
	Command []string `toml:"command"`
}

// LoadUser reads config.toml. A missing file is an empty configuration.
func LoadUser(path, home string) (User, error) {
	u := User{Secrets: map[string]secret.Backend{}, Approvals: Approvals{Desktop: true}}
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
	names := make([]string, 0, len(f.Secrets))
	for name := range f.Secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	var errs []error
	for _, name := range names {
		s := f.Secrets[name]
		b := secret.Backend{File: expandHome(s.File, home), Command: s.Command}
		if err := b.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("secret %q: %w", name, err))
			continue
		}
		if b.File != "" && !filepath.IsAbs(b.File) {
			errs = append(errs, fmt.Errorf("secret %q: file %q must be absolute or start with ~/", name, s.File))
			continue
		}
		u.Secrets[name] = b
	}
	if err := errors.Join(errs...); err != nil {
		return User{}, fmt.Errorf("%s: %w", path, err)
	}
	return u, nil
}

func expandHome(p, home string) string {
	if p == "~" {
		return home
	}
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		return filepath.Join(home, rest)
	}
	return p
}
