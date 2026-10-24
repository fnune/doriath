package doctor

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/session"
	"github.com/fnune/doriath/internal/vcstools"
)

// DefaultProfile is the profile doctor checks a repository against when
// neither --profile nor the repository's .envrc names one.
const DefaultProfile = "default"

func repository(opts Options) []Result {
	if opts.Dir == "" {
		return nil
	}
	exists := func(p string) bool { _, err := os.Lstat(p); return err == nil }
	repo := profile.FindRepository(opts.Dir, exists)
	if repo == "" {
		return nil
	}
	current := opts.Dir
	name, from := opts.Profile, "--profile"
	if envrc, dir := envrcProfile(opts.Dir, repo); envrc != "" {
		current = dir
		if name == "" {
			name, from = envrc, ".envrc"
		}
	}
	if name == "" {
		name, from = DefaultProfile, "the default"
	}
	label := "repository " + repo
	prof, err := opts.Loader.Load(name)
	if err != nil {
		if from == "the default" {
			return []Result{{Name: label, Level: Note, Detail: "no profile for it: add use doriath PROFILE to its .envrc, or run doriath doctor --profile NAME"}}
		}
		return []Result{{Name: label, Level: Problem, Detail: fmt.Sprintf("profile %s, from %s: %v", name, from, err)}}
	}
	resolved, err := prof.Resolve(profile.Start{Current: current, Repository: repo, Exists: exists}, opts.Paths.Home)
	if err != nil {
		return []Result{{Name: label, Level: Problem, Detail: fmt.Sprintf("profile %s: %v", name, err)}}
	}
	out := []Result{access(label+" with profile "+name, resolved, repo)}
	out = append(out, signing(resolved, opts.VCS))
	return out
}

func envrcProfile(dir, repo string) (name, envrcDir string) {
	for d := dir; ; d = filepath.Dir(d) {
		if data, err := os.ReadFile(filepath.Join(d, ".envrc")); err == nil {
			if name := useDoriath(data); name != "" {
				return name, d
			}
		}
		if d == repo || d == filepath.Dir(d) {
			return "", ""
		}
	}
}

func useDoriath(envrc []byte) string {
	lines := bufio.NewScanner(bytes.NewReader(envrc))
	for lines.Scan() {
		f := strings.Fields(lines.Text())
		if len(f) < 3 || f[0] != "use" || f[1] != "doriath" {
			continue
		}
		var names []string
		for i := 2; i < len(f) && !strings.HasPrefix(f[i], "-"); i++ {
			names = append(names, f[i])
		}
		return strings.Join(names, "+")
	}
	return ""
}

func access(label string, p *profile.Profile, repo string) Result {
	var deepest *profile.Mount
	for i, m := range p.Mounts {
		if within(repo, m.Path) && (deepest == nil || len(m.Path) >= len(deepest.Path)) {
			deepest = &p.Mounts[i]
		}
	}
	switch {
	case deepest == nil, deepest.Mode == profile.ModeHide:
		return Result{Name: label, Level: Problem, Detail: "the jail does not show its root, so git and jj in the jail cannot find it"}
	case deepest.Mode == profile.ModeWrite:
		return Result{Name: label, Level: OK, Detail: "the agent writes the checkout and commits"}
	case p.VCSStore:
		return Result{Name: label, Level: OK, Detail: "the agent commits through the store, and the checkout stays read-only"}
	}
	return Result{Name: label, Level: Note, Detail: "the agent reads it but cannot commit: add vcs-readwrite or vcs-readonly to the profile"}
}

func signing(p *profile.Profile, tools []vcstools.Tool) Result {
	if err := session.CheckSigning(p, tools); err != nil {
		return Result{Name: "signing", Level: Problem, Detail: err.Error()}
	}
	switch {
	case p.SigningKey != "":
		return Result{Name: "signing", Level: OK, Detail: "with the secret " + p.SigningKey}
	case p.Unsigned:
		return Result{Name: "signing", Level: OK, Detail: "off, as the profile says"}
	}
	return Result{Name: "signing", Level: OK, Detail: "neither you nor the profile signs commits"}
}

func within(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}
