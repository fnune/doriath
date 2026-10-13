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

// repoClone is the agent's private clone of one repository. Its objects
// borrow from the source repository through an alternate that points inside
// the jail, so a clone of a large repository costs almost nothing.
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
	c := repoClone{
		source:    m.Path,
		dir:       filepath.Join(s.cacheRoot(), "clones", filepath.Base(m.Path)+"-"+s.id),
		objects:   filepath.Join(common, "objects"),
		jailObjs:  jail.InJail("origin-" + strconv.Itoa(i) + "/objects"),
		base:      base,
		refPrefix: fmt.Sprintf("refs/girdle/%s/%s/", s.req.Profile.Name, s.id),
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
	if url, err := s.git(ctx, "-C", m.Path, "remote", "get-url", "origin"); err == nil && url != "" {
		if _, err := s.git(ctx, "-C", c.dir, "remote", "set-url", "origin", url); err != nil {
			return repoClone{}, err
		}
	} else if _, err := s.git(ctx, "-C", c.dir, "remote", "remove", "origin"); err != nil {
		return repoClone{}, err
	}
	// The source's object directory is mounted read-only inside the jail at a
	// path of its own, because the clone itself sits at the source's path.
	if err := os.MkdirAll(filepath.Join(s.jailDir, "origin-"+strconv.Itoa(i), "objects"), 0o700); err != nil {
		return repoClone{}, err
	}
	alternates := filepath.Join(c.dir, ".git", "objects", "info", "alternates")
	if err := writeFile(alternates, []byte(c.jailObjs+"\n"), 0o644); err != nil {
		return repoClone{}, err
	}
	return c, nil
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

// landClones brings the clone's branches into the source repository as
// refs under refs/girdle, where the person reviews them. Nothing touches the
// source's working tree, and jj ignores that namespace.
func (s *Session) landClones(ctx context.Context) []string {
	var lines []string
	for _, c := range s.clones {
		// The jail is gone, so the clone's alternate goes back to the host
		// path. git ignores GIT_ALTERNATE_OBJECT_DIRECTORIES for the other
		// side of a local fetch, so the file itself has to change.
		alternates := filepath.Join(c.dir, ".git", "objects", "info", "alternates")
		if err := writeFile(alternates, []byte(c.objects+"\n"), 0o644); err != nil {
			lines = append(lines, fmt.Sprintf("girdle: could not bring back work from %s: %v", c.dir, err))
			continue
		}
		if _, err := s.git(ctx, "-C", c.source, "fetch", "--quiet", "--no-write-fetch-head", c.dir,
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
				// A detached HEAD only matters when no branch holds its commit.
				if sha, err := s.git(ctx, "-C", c.source, "rev-parse", ref); err == nil && tips[sha] {
					continue
				}
			}
			n, err := s.git(ctx, "-C", c.source, "rev-list", "--count", c.base+".."+ref)
			if err != nil || n == "0" {
				continue
			}
			lines = append(lines, fmt.Sprintf("girdle: %s has %s new commit(s) in %s. Review: git -C %s log -p %s..%s",
				strings.TrimPrefix(ref, c.refPrefix), n, filepath.Base(c.source), c.source, c.base[:12], ref))
		}
		s.log.Write("clone-landed", map[string]string{"source": c.source, "refs": c.refPrefix})
	}
	return lines
}
