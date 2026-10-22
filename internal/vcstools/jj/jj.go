// Package jj is doriath's view of jj: whether your config signs commits,
// and the jail's config, which reads yours and then overrides its signing.
package jj

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/fnune/doriath/internal/vcstools"
)

const configFile = "jj.toml"

type Tool struct {
	home string
	kind func(string) string
}

// New reads your jj config under home; kind returns "file", "dir" or "" for
// a path.
func New(home string, kind func(string) string) Tool { return Tool{home: home, kind: kind} }

func (Tool) Name() string { return "jj" }

func (t Tool) configs() []string {
	dir := filepath.Join(t.home, ".config", "jj")
	var out []string
	for _, p := range []string{filepath.Join(dir, "config.toml"), filepath.Join(dir, "conf.d")} {
		if t.kind(p) != "" {
			out = append(out, p)
		}
	}
	return out
}

// HostSigns reads signing.behavior from your config. keep counts as
// signing: jj signs again each commit it rewrites that was signed before.
func (t Tool) HostSigns() string {
	var files []string
	for _, p := range t.configs() {
		if t.kind(p) == "dir" {
			matches, _ := filepath.Glob(filepath.Join(p, "*.toml"))
			slices.Sort(matches)
			files = append(files, matches...)
			continue
		}
		files = append(files, p)
	}
	behavior := ""
	for _, f := range files {
		var c struct {
			Signing struct {
				Behavior string `toml:"behavior"`
			} `toml:"signing"`
		}
		if data, err := os.ReadFile(f); err == nil && toml.Unmarshal(data, &c) == nil && c.Signing.Behavior != "" {
			behavior = c.Signing.Behavior
		}
	}
	if slices.Contains([]string{"own", "force", "keep"}, behavior) {
		return "signing.behavior = " + behavior
	}
	return ""
}

func (t Tool) Jail(j vcstools.Jail) vcstools.Config {
	override := "[signing]\nbehavior = \"drop\"\n"
	if j.SigningKey != "" {
		override = fmt.Sprintf("[signing]\nbehavior = \"own\"\nbackend = \"ssh\"\nkey = %q\n", j.SigningKey)
	}
	return vcstools.Config{
		Files: map[string][]byte{configFile: []byte(override)},
		Env:   map[string]string{"JJ_CONFIG": strings.Join(append(t.configs(), j.Path(configFile)), ":")},
	}
}
