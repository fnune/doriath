package session

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"time"

	"github.com/fnune/girdle/internal/config"
	"github.com/fnune/girdle/internal/jail"
	"github.com/fnune/girdle/internal/profile"
	"github.com/fnune/girdle/internal/vcs"
)

// storeRepositories are the main repositories whose store the jail can
// write, when the profile asks for it: those in its mounts, and those whose
// linked worktrees or workspaces are there.
func storeRepositories(p *profile.Profile) []string {
	if !p.VCSStore {
		return nil
	}
	var out []string
	for _, m := range p.Mounts {
		if m.Mode == profile.ModeHide {
			continue
		}
		for _, repo := range jail.Repositories(m.Path, osHost{}) {
			if root := vcs.Root(repo); !slices.Contains(out, root) {
				out = append(out, root)
			}
		}
	}
	return out
}

// withLinkedStores adds, read-only, the main repository's store of each
// linked git worktree and secondary jj workspace in a read mount, so git and
// jj work there, and the vcs module makes the store's data writable.
func withLinkedStores(p *profile.Profile) *profile.Profile {
	if !p.VCSStore {
		return p
	}
	visible := func(path string) bool {
		for _, m := range p.Mounts {
			if m.Mode != profile.ModeHide && within(path, m.Path) {
				return true
			}
		}
		return false
	}
	out := *p
	out.Mounts = slices.Clone(p.Mounts)
	for _, m := range p.Mounts {
		if m.Mode == profile.ModeHide {
			continue
		}
		for _, repo := range jail.Repositories(m.Path, osHost{}) {
			git, jj := vcs.Linked(repo)
			for _, store := range []string{git, jj} {
				if store != "" && (osHost{}).Kind(store) == "dir" && !visible(store) {
					out.Mounts = append(out.Mounts, profile.Mount{Path: store, Mode: profile.ModeRead})
				}
			}
		}
	}
	return &out
}

func (s *Session) vcsTools() vcs.Tools { return vcs.Tools{Git: s.deps.Git, JJ: s.deps.JJ} }

func recordPath(paths config.Paths, id string) string {
	return filepath.Join(paths.Backups(), id+".json")
}

func (s *Session) startRepositories(ctx context.Context) error {
	repos := storeRepositories(s.req.Profile)
	if len(repos) == 0 {
		return nil
	}
	if s.deps.Git == "" {
		return fmt.Errorf("the vcs module needs git on the host to keep your branches recoverable")
	}
	for _, repo := range repos {
		notes, err := vcs.Prepare(ctx, s.vcsTools(), repo, jail.JJLockFiles)
		if err != nil {
			return fmt.Errorf("prepare %s: %w", repo, err)
		}
		for _, n := range notes {
			fmt.Fprintf(s.deps.Stderr, "girdle: %s\n", n)
		}
	}
	rec := &vcs.Record{Session: s.id, Profile: s.req.Profile.Name, Started: time.Now()}
	for _, m := range s.req.Profile.Mounts {
		if m.Mode == profile.ModeWrite {
			rec.Writable = append(rec.Writable, m.Path)
		}
	}
	if err := vcs.Start(ctx, s.vcsTools(), filepath.Join(s.deps.Paths.Backups(), s.id), rec, repos); err != nil {
		return err
	}
	return rec.Save(recordPath(s.deps.Paths, s.id))
}

func (s *Session) finishRepositories() {
	path := recordPath(s.deps.Paths, s.id)
	rec, err := vcs.Load(path)
	if err != nil {
		return
	}
	if err := FinishRecord(context.Background(), s.deps.Paths, s.vcsTools(), rec, s.deps.Stderr); err != nil {
		fmt.Fprintf(s.deps.Stderr, "girdle: %v\n", err)
	}
}

// FinishRecord runs the end step of a session's repositories and saves the
// result. girdle run calls it for sessions that ended without one.
func FinishRecord(ctx context.Context, paths config.Paths, t vcs.Tools, rec *vcs.Record, w io.Writer) error {
	err := vcs.Finish(ctx, t, filepath.Join(paths.Backups(), rec.Session), rec, w)
	if saveErr := rec.Save(recordPath(paths, rec.Session)); err == nil {
		err = saveErr
	}
	return err
}
