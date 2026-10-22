package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/modules"
	"github.com/fnune/doriath/internal/profile"
)

var profileSections = []struct{ prefix, title string }{
	{"mount ", "Mounts"},
	{"cache ", "Caches"},
	{"device ", "Devices"},
	{"host ", "Hosts"},
	{"http ", "Hosts the proxy inspects"},
	{"env ", "Environment"},
	{"mcp ", "MCP servers"},
	{"image ", "Container images"},
	{"secret ", "Secrets"},
}

func printProfile(w io.Writer, p *profile.Profile) error {
	fmt.Fprintf(w, "%s: %s\n", p.Name, p.Description)
	fmt.Fprintf(w, "Modules: %s\n", strings.Join(p.Modules, ", "))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, section := range profileSections {
		var keys []string
		for key := range p.Sources {
			if strings.HasPrefix(key, section.prefix) {
				keys = append(keys, key)
			}
		}
		if len(keys) == 0 {
			continue
		}
		sort.Strings(keys)
		fmt.Fprintf(tw, "\n%s\n", section.title)
		for _, key := range keys {
			fmt.Fprintf(tw, "  %s\t%s\n", strings.TrimPrefix(key, section.prefix), strings.Join(p.Sources[key], ", "))
		}
	}
	return tw.Flush()
}

type moduleSource struct {
	name     string
	builtin  []byte
	userPath string
}

func (m moduleSource) origin() string {
	switch {
	case m.userPath != "" && m.builtin != nil:
		return "yours, in place of the built-in"
	case m.userPath != "":
		return "yours"
	}
	return "built in"
}

func (m moduleSource) data() ([]byte, error) {
	if m.userPath != "" {
		return os.ReadFile(m.userPath)
	}
	return m.builtin, nil
}

func findModule(p config.Paths, name string) (moduleSource, error) {
	m := moduleSource{name: name}
	if data, err := fs.ReadFile(modules.FS, name+".toml"); err == nil {
		m.builtin = data
	}
	user := filepath.Join(p.Modules(), name+".toml")
	if _, err := os.Stat(user); err == nil {
		m.userPath = user
	}
	if m.builtin == nil && m.userPath == "" {
		return m, fmt.Errorf("no module named %s; doriath modules list shows them", name)
	}
	return m, nil
}

func moduleNames(p config.Paths) ([]string, error) {
	var names []string
	for _, src := range []fs.FS{modules.FS, os.DirFS(p.Modules())} {
		entries, err := fs.ReadDir(src, ".")
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if name, ok := strings.CutSuffix(e.Name(), ".toml"); ok && !e.IsDir() && !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return names, nil
}

func moduleSummary(data []byte) string {
	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line, ok := strings.CutPrefix(scanner.Text(), "#")
		if !ok {
			break
		}
		lines = append(lines, strings.TrimSpace(line))
	}
	text := strings.Join(lines, " ")
	if i := strings.Index(text, ". "); i >= 0 {
		text = text[:i+1]
	}
	return text
}

func cmdModulesFromArgs(args []string, stdin io.Reader, stdout io.Writer) error {
	p, err := paths()
	if err != nil {
		return err
	}
	return cmdModules(p, loader(p), args, stdin, stdout)
}

func cmdModules(p config.Paths, l *profile.Loader, args []string, stdin io.Reader, stdout io.Writer) error {
	usage := errors.New("modules: usage: doriath modules [list | show NAME [--path] | edit NAME]")
	if len(args) == 0 || args[0] == "list" {
		names, err := moduleNames(p)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		for _, name := range names {
			m, err := findModule(p, name)
			if err != nil {
				return err
			}
			data, err := m.data()
			if err != nil {
				return err
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\n", name, m.origin(), moduleSummary(data))
		}
		return tw.Flush()
	}
	switch args[0] {
	case "show":
		flags := flag.NewFlagSet("modules show", flag.ContinueOnError)
		path := flags.Bool("path", false, "print a path to the module file instead of its text")
		if len(args) < 2 {
			return usage
		}
		name := args[1]
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		m, err := findModule(p, name)
		if err != nil {
			return err
		}
		if !*path {
			data, err := m.data()
			if err != nil {
				return err
			}
			_, err = stdout.Write(data)
			return err
		}
		if m.userPath != "" {
			fmt.Fprintln(stdout, m.userPath)
			return nil
		}
		copied, err := builtinCopy(p, m)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, copied)
		return nil
	case "edit":
		if len(args) != 2 {
			return usage
		}
		return modulesEdit(p, l, args[1], stdin, stdout)
	}
	return usage
}

func builtinCopy(p config.Paths, m moduleSource) (string, error) {
	dir := filepath.Join(p.Cache, "modules", version)
	path := filepath.Join(dir, m.name+".toml")
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, m.builtin) {
		return path, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	_ = os.Chmod(path, 0o600)
	if err := os.WriteFile(path, m.builtin, 0o400); err != nil {
		return "", err
	}
	return path, os.Chmod(path, 0o400)
}

func modulesEdit(p config.Paths, l *profile.Loader, name string, in io.Reader, w io.Writer) error {
	path := filepath.Join(p.Modules(), name+".toml")
	info, err := os.Lstat(path)
	switch {
	case err == nil && info.Mode()&os.ModeSymlink != 0:
		if target, _ := filepath.EvalSymlinks(path); strings.HasPrefix(target, "/nix/store/") {
			return fmt.Errorf("module %s is managed by home-manager (%s): change it in your nix configuration", name, target)
		}
	case errors.Is(err, os.ErrNotExist):
		m, findErr := findModule(p, name)
		if findErr != nil {
			return findErr
		}
		if err := os.MkdirAll(p.Modules(), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, m.builtin, 0o600); err != nil {
			return err
		}
		fmt.Fprintf(w, "Copied the built-in %s module to %s. Your copy replaces it in every profile.\n", name, path)
	case err != nil:
		return err
	}
	return editUntilValid(path, "Module "+name, func() error { return l.CheckModule(name) }, in, w)
}
