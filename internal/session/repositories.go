package session

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/fnune/girdle/internal/config"
	"github.com/fnune/girdle/internal/jail"
	"github.com/fnune/girdle/internal/profile"
	"github.com/fnune/girdle/internal/vcs"
)

// storeRepositories are the repositories whose store the jail can write:
// those inside read-only mounts, when the profile asks for it.
func storeRepositories(p *profile.Profile) []string {
	if !p.VCSStore {
		return nil
	}
	var out []string
	for _, m := range p.Mounts {
		if m.Mode == profile.ModeRead {
			out = append(out, jail.Repositories(m.Path, osHost{})...)
		}
	}
	return out
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
