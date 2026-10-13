package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fnune/girdle/internal/jail"
	"github.com/fnune/girdle/internal/profile"
)

type repoClone struct {
	source    string
	dir       string
	objects   string
	jailObjs  string
	base      string
	refPrefix string
}

func (s *Session) git(ctx context.Context, args ...string) (string, error) {
	if s.deps.Git == "" {
		return "", errors.New("clone mounts need git on PATH")
	}
	cmd := exec.CommandContext(ctx, s.deps.Git, args...)
	cmd.Env = os.Environ()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

func (s *Session) prepareClones(ctx context.Context) error {
	for i, m := range s.req.Profile.Mounts {
		if m.Mode != profile.ModeClone {
			continue
		}
		c, err := s.makeClone(ctx, i, m)
		if err != nil {
			return fmt.Errorf("clone %s: %w", m.Path, err)
		}
		s.clones = append(s.clones, c)
		s.log.Write("clone", map[string]string{"source": c.source, "dir": c.dir, "base": c.base})
	}
	return nil
}

func (s *Session) makeClone(ctx context.Context, i int, m profile.Mount) (repoClone, error) {
	common, err := s.git(ctx, "-C", m.Path, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return repoClone{}, err
	}
	ref := m.Ref
	if ref == "" {
		ref = "HEAD"
	}
	base, err := s.git(ctx, "-C", m.Path, "rev-parse", "--verify", ref+"^{commit}")
	if err != nil {
		return repoClone{}, err
	}
	owner := s.id
	if s.req.CloneFrom != "" {
		owner = s.req.CloneFrom
	}
	c := repoClone{
		source:    m.Path,
		dir:       filepath.Join(s.cacheRoot(), "clones", filepath.Base(m.Path)+"-"+owner),
		objects:   filepath.Join(common, "objects"),
		jailObjs:  jail.InJail("origin-" + strconv.Itoa(i) + "/objects"),
		base:      base,
		refPrefix: fmt.Sprintf("refs/girdle/%s/%s/", s.req.Profile.Name, s.id),
	}
	baseFile := c.dir + ".base"
	if s.req.CloneFrom != "" {
		data, err := os.ReadFile(baseFile)
		if err != nil {
			return repoClone{}, fmt.Errorf("no clone from session %s: run girdle run without --clone-from, or check ~/.cache/girdle/agents/%s/clones", s.req.CloneFrom, s.req.Profile.Name)
		}
		c.base = strings.TrimSpace(string(data))
		if !isObjectID(c.base) {
			return repoClone{}, fmt.Errorf("%s does not hold a commit id", baseFile)
		}
		return c, s.pointAlternates(c, i)
	}
	if err := os.MkdirAll(filepath.Dir(c.dir), 0o700); err != nil {
		return repoClone{}, err
	}
	if _, err := s.git(ctx, "clone", "--quiet", "--shared", "--no-checkout", m.Path, c.dir); err != nil {
		return repoClone{}, err
	}
	if _, err := s.git(ctx, "-C", c.dir, "checkout", "--quiet", "--detach", base); err != nil {
		return repoClone{}, err
	}
	if err := s.dropBranchesTheAgentDidNotMake(ctx, c.dir); err != nil {
		return repoClone{}, err
	}
	if err := writeFile(baseFile, []byte(base+"\n"), 0o600); err != nil {
		return repoClone{}, err
	}
	if url, err := s.git(ctx, "-C", m.Path, "remote", "get-url", "origin"); err == nil && url != "" {
		if _, err := s.git(ctx, "-C", c.dir, "remote", "set-url", "origin", url); err != nil {
			return repoClone{}, err
		}
	} else if _, err := s.git(ctx, "-C", c.dir, "remote", "remove", "origin"); err != nil {
		return repoClone{}, err
	}
	return c, s.pointAlternates(c, i)
}

func (s *Session) pointAlternates(c repoClone, i int) error {
	if err := os.MkdirAll(filepath.Join(s.jailDir, "origin-"+strconv.Itoa(i), "objects"), 0o700); err != nil {
		return err
	}
	alternates := filepath.Join(c.dir, ".git", "objects", "info", "alternates")
	return writeFile(alternates, []byte(c.jailObjs+"\n"), 0o644)
}

func (s *Session) cloneBinds() []jail.Bind {
	var out []jail.Bind
	for _, c := range s.clones {
		out = append(out, jail.Bind{Source: c.objects, Dest: c.jailObjs, ReadOnly: true})
	}
	return out
}

func (s *Session) cloneDirs() map[string]string {
	out := map[string]string{}
	for _, c := range s.clones {
		out[c.source] = c.dir
	}
	return out
}

func (s *Session) landClones(ctx context.Context) []string {
	var lines []string
	for _, c := range s.clones {
		alternates := filepath.Join(c.dir, ".git", "objects", "info", "alternates")
		if err := writeFile(alternates, []byte(c.objects+"\n"), 0o644); err != nil {
			lines = append(lines, fmt.Sprintf("girdle: could not bring back work from %s: %v", c.dir, err))
			continue
		}
		if _, err := s.git(ctx, "-C", c.source, "-c", "protocol.allow=never", "-c", "protocol.file.allow=always",
			"fetch", "--quiet", "--no-write-fetch-head", "--upload-pack="+shellWord(s.deps.Git)+" upload-pack", c.dir,
			"+refs/heads/*:"+c.refPrefix+"*", "+HEAD:"+c.refPrefix+"HEAD"); err != nil {
			lines = append(lines, fmt.Sprintf("girdle: could not bring back work from %s: %v", c.dir, err))
			continue
		}
		refs, err := s.git(ctx, "-C", c.source, "for-each-ref", "--format=%(refname)", c.refPrefix)
		if err != nil {
			continue
		}
		tips := map[string]bool{}
		for _, ref := range strings.Fields(refs) {
			if !strings.HasSuffix(ref, "/HEAD") {
				if sha, err := s.git(ctx, "-C", c.source, "rev-parse", ref); err == nil {
					tips[sha] = true
				}
			}
		}
		for _, ref := range strings.Fields(refs) {
			if strings.HasSuffix(ref, "/HEAD") {
				if sha, err := s.git(ctx, "-C", c.source, "rev-parse", ref); err == nil && tips[sha] {
					continue
				}
			}
			n, err := s.git(ctx, "-C", c.source, "rev-list", "--count", c.base+".."+ref)
			if err != nil {
				continue
			}
			if n == "0" {
				_, _ = s.git(ctx, "-C", c.source, "update-ref", "-d", ref)
				continue
			}
			lines = append(lines, fmt.Sprintf("girdle: %s has %s new commit(s) in %s. Review: git -C %s log -p %s..%s",
				strings.TrimPrefix(ref, c.refPrefix), n, filepath.Base(c.source), c.source, c.base[:12], ref))
		}
		s.log.Write("clone-landed", map[string]string{"source": c.source, "refs": c.refPrefix})
		lines = append(lines, s.retireClone(ctx, c)...)
	}
	return lines
}

func (s *Session) retireClone(ctx context.Context, c repoClone) []string {
	status, err := s.gitInClone(ctx, c.dir, "status", "--porcelain", "--untracked-files=normal")
	if err != nil {
		return []string{fmt.Sprintf("girdle: kept %s: could not check it for uncommitted changes: %v", c.dir, err)}
	}
	if status != "" {
		return []string{fmt.Sprintf("girdle: %s has uncommitted changes in %s. Resume them with: girdle run --clone-from %s", filepath.Base(c.source), c.dir, s.cloneOwner())}
	}
	if err := os.RemoveAll(c.dir); err != nil {
		return []string{fmt.Sprintf("girdle: could not remove %s: %v", c.dir, err)}
	}
	_ = os.Remove(c.dir + ".base")
	s.log.Write("clone-removed", map[string]string{"dir": c.dir})
	return nil
}

func (s *Session) cloneOwner() string {
	if s.req.CloneFrom != "" {
		return s.req.CloneFrom
	}
	return s.id
}

func (s *Session) gitInClone(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, s.deps.Git, append([]string{"-C", dir, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

func isObjectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func shellWord(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (s *Session) dropBranchesTheAgentDidNotMake(ctx context.Context, dir string) error {
	heads, err := s.git(ctx, "-C", dir, "for-each-ref", "--format=%(refname)", "refs/heads/")
	if err != nil {
		return err
	}
	for _, ref := range strings.Fields(heads) {
		if _, err := s.git(ctx, "-C", dir, "update-ref", "-d", ref); err != nil {
			return err
		}
	}
	return nil
}
