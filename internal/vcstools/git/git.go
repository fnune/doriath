package git

import (
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/fnune/doriath/internal/vcstools"
)

const configFile = "gitconfig"

var hostFiles = []struct{ key, jailName, xdgDefault string }{
	{"core.excludesfile", "gitignore", "git/ignore"},
	{"core.attributesfile", "gitattributes", "git/attributes"},
	{"commit.template", "gitmessage", ""},
}

type Tool struct {
	desktop []byte
	files   map[string][]byte
}

func New(desktop []byte, files map[string][]byte) Tool { return Tool{desktop: desktop, files: files} }

func HostFiles(desktop []byte, home string, getenv func(string) string, read func(string) ([]byte, error)) map[string][]byte {
	set := map[string]string{}
	for _, e := range parseGitList(desktop) {
		set[strings.ToLower(e.key)] = e.value
	}
	xdg := getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		xdg = filepath.Join(home, ".config")
	}
	out := map[string][]byte{}
	for _, f := range hostFiles {
		path := set[f.key]
		switch {
		case path == "~" || strings.HasPrefix(path, "~/"):
			path = filepath.Join(home, path[1:])
		case path == "" && f.xdgDefault != "":
			path = filepath.Join(xdg, f.xdgDefault)
		case path == "":
			continue
		}
		if data, err := read(path); err == nil {
			out[f.key] = data
		}
	}
	return out
}

func (Tool) Name() string { return "git" }

func (t Tool) HostSigns() string {
	for _, e := range parseGitList(t.desktop) {
		k := strings.ToLower(e.key)
		if (k == "commit.gpgsign" || k == "tag.gpgsign") && slices.Contains([]string{"true", "yes", "on", "1"}, strings.ToLower(e.value)) {
			return k
		}
	}
	return ""
}

func (t Tool) Jail(j vcstools.Jail) vcstools.Config {
	files := map[string][]byte{}
	paths := map[string]string{}
	for _, f := range hostFiles {
		if data, ok := t.files[f.key]; ok {
			files[f.jailName] = data
			paths[f.key] = j.Path(f.jailName)
		}
	}
	files[configFile] = config(t.desktop, j, paths)
	return vcstools.Config{
		Files: files,
		Env:   map[string]string{"GIT_CONFIG_GLOBAL": j.Path(configFile)},
	}
}

var gitDenied = []string{
	"credential.", "url.", "include.", "includeif.", "http.", "sendemail.", "remote.", "branch.",
	"core.sshcommand", "core.askpass", "core.hookspath", "core.fsmonitor", "core.editor",
	"gpg.program", "gpg.ssh.program", "gpg.ssh.allowedsignersfile", "user.signingkey",
}

func gitAllowed(key string) bool {
	k := strings.ToLower(key)
	for _, d := range gitDenied {
		if strings.HasSuffix(d, ".") && strings.HasPrefix(k, d) || k == d {
			return false
		}
	}
	return true
}

var keyGitPrints = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[^\n]*)?\.[A-Za-z][A-Za-z0-9-]*$`)

type gitEntry struct{ key, value string }

func parseGitList(data []byte) []gitEntry {
	var out []gitEntry
	for _, rec := range bytes.Split(data, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		key, value, _ := strings.Cut(string(rec), "\n")
		out = append(out, gitEntry{key: key, value: value})
	}
	return out
}

func config(desktop []byte, j vcstools.Jail, files map[string]string) []byte {
	var entries []gitEntry
	for _, e := range parseGitList(desktop) {
		if keyGitPrints.MatchString(e.key) && gitAllowed(e.key) {
			entries = append(entries, e)
		}
	}
	set := func(key, value string) {
		entries = append(entries, gitEntry{key: key, value: value})
	}
	if j.SigningKey != "" {
		set("gpg.format", "ssh")
		set("user.signingkey", j.SigningKey)
		set("commit.gpgsign", "true")
	} else {
		set("commit.gpgsign", "false")
		set("tag.gpgsign", "false")
	}
	for _, f := range hostFiles {
		if p, ok := files[f.key]; ok {
			set(f.key, p)
		}
	}
	set("credential.helper", "")
	// Relative worktree paths need an extension in the repository's
	// .git/config, which the jail cannot write and nix cannot read. The jail
	// sees each repository where you do, so absolute paths serve both.
	set("worktree.useRelativePaths", "false")
	set("gc.auto", "0")
	set("maintenance.auto", "false")
	if j.SSHCommand != "" {
		set("core.sshCommand", j.SSHCommand)
	}
	for _, r := range j.RewriteSSH {
		https := fmt.Sprintf("url.https://%s/.insteadof", r.Host)
		for _, host := range append([]string{r.Host}, r.SSHHosts...) {
			set(https, fmt.Sprintf("%s@%s:", r.User, host))
			set(https, fmt.Sprintf("ssh://%s@%s/", r.User, host))
			if r.Port != 22 {
				set(https, fmt.Sprintf("ssh://%s@%s:%d/", r.User, host, r.Port))
			}
		}
	}
	return renderGit(entries)
}

func renderGit(entries []gitEntry) []byte {
	type section struct {
		header string
		lines  []string
	}
	var order []string
	sections := map[string]*section{}
	for _, e := range entries {
		first := strings.Index(e.key, ".")
		last := strings.LastIndex(e.key, ".")
		if first < 0 {
			continue
		}
		name := e.key[last+1:]
		header := fmt.Sprintf("[%s]", e.key[:first])
		if first != last {
			sub := e.key[first+1 : last]
			header = fmt.Sprintf("[%s %s]", e.key[:first], quote(sub))
		}
		s, ok := sections[header]
		if !ok {
			s = &section{header: header}
			sections[header] = s
			order = append(order, header)
		}
		s.lines = append(s.lines, fmt.Sprintf("\t%s = %s", name, quote(e.value)))
	}
	var b bytes.Buffer
	for _, h := range order {
		b.WriteString(h + "\n")
		for _, l := range sections[h].lines {
			b.WriteString(l + "\n")
		}
	}
	return b.Bytes()
}

func quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`)
	return `"` + r.Replace(s) + `"`
}
