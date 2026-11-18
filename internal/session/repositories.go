package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fnune/doriath/internal/audit"
	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/jail"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/term"
	"github.com/fnune/doriath/internal/vcs"
)

func storeRepositories(p *profile.Profile, host jail.Host) []string {
	if !p.VCSStore {
		return nil
	}
	var out []string
	for _, m := range p.Mounts {
		if m.Mode == profile.ModeHide {
			continue
		}
		for _, repo := range jail.Repositories(m.Path, host) {
			if root := vcs.Root(repo); !slices.Contains(out, root) {
				out = append(out, root)
			}
		}
	}
	return out
}

func withLinkedStores(p *profile.Profile, host jail.Host) *profile.Profile {
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
		for _, repo := range jail.Repositories(m.Path, host) {
			git, jj := vcs.Linked(repo)
			for _, store := range []string{git, jj} {
				if store != "" && host.Kind(store) == "dir" && !visible(store) {
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
	notes, err := s.addRepositories(ctx, s.req.Profile, s.listings)
	for _, n := range notes {
		s.notes = append(s.notes, note{term.Info, n})
	}
	return err
}

type repositoryRecord struct {
	mu       sync.Mutex
	rec      *vcs.Record
	repairs  *repairLog
	stop     func()
	finished bool
	checked  map[string]bool
}

func (s *Session) finishInterruptedSessions(ctx context.Context) {
	r := &s.repos
	r.mu.Lock()
	defer r.mu.Unlock()
	_, stores := s.unrecorded(s.req.Profile, s.listings)
	for _, n := range s.interrupted(ctx, stores) {
		s.notes = append(s.notes, note{term.Info, n})
	}
}

func (s *Session) unrecorded(p *profile.Profile, host jail.Host) (repos, stores []string) {
	r := &s.repos
	for _, repo := range storeRepositories(p, host) {
		if r.rec == nil || !slices.ContainsFunc(r.rec.Repos, func(known vcs.Repo) bool { return known.GitDir == vcs.Store(repo) }) {
			repos = append(repos, repo)
			stores = append(stores, vcs.Store(repo))
		}
	}
	return repos, stores
}

func (s *Session) interrupted(ctx context.Context, stores []string) []string {
	r := &s.repos
	if r.checked == nil {
		r.checked = map[string]bool{}
	}
	var unchecked []string
	for _, store := range stores {
		if !r.checked[store] {
			r.checked[store] = true
			unchecked = append(unchecked, store)
		}
	}
	if s.deps.Interrupted == nil || len(unchecked) == 0 {
		return nil
	}
	return s.deps.Interrupted(ctx, unchecked)
}

func (s *Session) dropUnusedRepositories() {
	r := &s.repos
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stop != nil {
		r.stop()
	}
	r.finished = true
	_ = os.RemoveAll(filepath.Join(s.deps.Paths.Backups(), s.id))
	_ = os.Remove(recordPath(s.deps.Paths, s.id))
}

func (s *Session) addRepositories(ctx context.Context, p *profile.Profile, host jail.Host) ([]string, error) {
	r := &s.repos
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finished {
		return nil, errors.New("the session has ended")
	}
	repos, stores := s.unrecorded(p, host)
	notes := s.interrupted(ctx, stores)
	if len(repos) == 0 {
		return notes, nil
	}
	if s.deps.Git == "" {
		return notes, fmt.Errorf("vcs-readwrite and vcs-readonly need git on the host to keep your branches recoverable")
	}
	for _, repo := range repos {
		n, err := vcs.Prepare(ctx, s.vcsTools(), repo)
		if err != nil {
			return notes, fmt.Errorf("prepare %s: %w", repo, err)
		}
		notes = append(notes, n...)
	}
	if r.stop != nil {
		r.stop()
	}
	if r.rec == nil {
		r.rec = &vcs.Record{Session: s.id, Profile: s.req.Profile.Name, Started: time.Now()}
		r.repairs = &repairLog{log: s.log}
	}
	for _, m := range p.Mounts {
		if m.Mode == profile.ModeWrite && !slices.Contains(r.rec.Writable, m.Path) {
			r.rec.Writable = append(r.rec.Writable, m.Path)
		}
	}
	err := vcs.Start(ctx, s.vcsTools(), filepath.Join(s.deps.Paths.Backups(), s.id), r.rec, repos)
	if saveErr := r.rec.Save(recordPath(s.deps.Paths, s.id)); err == nil {
		err = saveErr
	}
	s.watchWorktrees()
	return notes, err
}

func (s *Session) watchWorktrees() {
	r := &s.repos
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := vcs.Watch(ctx, r.rec, r.repairs); err != nil {
			term.New(s.deps.Stderr).Problem(fmt.Sprintf("agent worktrees are repaired only when the session ends: %v", err))
		}
	}()
	r.stop = func() {
		cancel()
		<-done
	}
}

type repairLog struct {
	log   *audit.Log
	lines bytes.Buffer
}

func (r *repairLog) Write(p []byte) (int, error) {
	r.log.Write("worktree-repair", map[string]any{"message": strings.TrimSpace(string(p))})
	return r.lines.Write(p)
}

func (s *Session) finishRepositories(fixed, needs io.Writer) {
	r := &s.repos
	r.mu.Lock()
	r.finished = true
	if r.stop != nil {
		r.stop()
		_, _ = fixed.Write(r.repairs.lines.Bytes())
	}
	r.mu.Unlock()
	path := recordPath(s.deps.Paths, s.id)
	rec, err := vcs.Load(path)
	if err != nil {
		return
	}
	if err := FinishRecord(context.Background(), s.deps.Paths, s.vcsTools(), rec, fixed, needs, s.deps.Stderr); err != nil {
		fmt.Fprintln(needs, err)
	}
}

// FinishRecord runs the end step of a session's repositories and saves the
// result. doriath run calls it for sessions that ended without one.
func FinishRecord(ctx context.Context, paths config.Paths, t vcs.Tools, rec *vcs.Record, fixed, needs, status io.Writer) error {
	bar := term.New(status).Bar()
	err := vcs.Finish(ctx, t, filepath.Join(paths.Backups(), rec.Session), rec, fixed, needs, packProgress(bar, time.Now))
	bar.Clear()
	if saveErr := rec.Save(recordPath(paths, rec.Session)); err == nil {
		err = saveErr
	}
	keepBackups(ctx, paths, t)
	return err
}

func packProgress(bar *term.Bar, now func() time.Time) vcs.Progress {
	var began time.Time
	var repo string
	return func(c vcs.PackCheck) {
		if c.Repo != repo {
			repo, began = c.Repo, now()
		}
		text := fmt.Sprintf("checking pack %d of %d (%s in all) that the agent wrote in %s", c.Pack, c.Packs, gigabytes(c.Bytes), filepath.Base(c.Repo))
		if left, ok := timeLeft(now().Sub(began), c.Done); ok {
			text = "about " + left + " left, " + text
		}
		bar.Show(c.Done, text)
	}
}

func timeLeft(elapsed time.Duration, done float64) (string, bool) {
	if done < 0.02 || done >= 1 || elapsed < 2*time.Second {
		return "", false
	}
	left := time.Duration(float64(elapsed) * (1 - done) / done)
	if left < time.Minute {
		return fmt.Sprintf("%d s", max(5, (int(left.Seconds())+4)/5*5)), true
	}
	return fmt.Sprintf("%d min", int(left.Minutes()+0.5)), true
}

func keepBackups(ctx context.Context, paths config.Paths, t vcs.Tools) {
	files, _ := filepath.Glob(filepath.Join(paths.Backups(), "*.json"))
	loaded, _ := vcs.LoadAll(files)
	var finished []*vcs.Record
	for _, rec := range loaded {
		if rec != nil && rec.Finished {
			finished = append(finished, rec)
		}
	}
	_ = vcs.KeepBackups(ctx, t, finished...)
}
