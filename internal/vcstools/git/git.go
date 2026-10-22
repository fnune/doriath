// Package git is doriath's view of git: whether your global config signs
// commits, and the jail's global config, built from yours with everything
// that points outside the jail left out.
package git

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/fnune/doriath/internal/vcstools"
)

const configFile = "gitconfig"

type Tool struct {
	desktop []byte
}

// New takes your global config as git config --global --includes --list -z
// prints it.
func New(desktop []byte) Tool { return Tool{desktop: desktop} }

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
	return vcstools.Config{
		Files: map[string][]byte{configFile: config(t.desktop, j)},
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

func config(desktop []byte, j vcstools.Jail) []byte {
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
	set("credential.helper", "")
	for _, r := range j.RewriteSSH {
		https := fmt.Sprintf("url.https://%s/.insteadof", r.Host)
		set(https, fmt.Sprintf("%s@%s:", r.User, r.Host))
		set(https, fmt.Sprintf("ssh://%s@%s/", r.User, r.Host))
		if r.Port != 22 {
			set(https, fmt.Sprintf("ssh://%s@%s:%d/", r.User, r.Host, r.Port))
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
