package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/fnune/girdle/internal/config"
	"github.com/fnune/girdle/internal/session"
	"github.com/fnune/girdle/internal/vcs"
)

func vcsTools() vcs.Tools { return vcs.Tools{Git: lookPath("git"), JJ: lookPath("jj")} }

// records lists the repository records of sessions that are not running.
func records(p config.Paths) ([]*vcs.Record, error) {
	files, err := filepath.Glob(filepath.Join(p.Backups(), "*.json"))
	if err != nil {
		return nil, err
	}
	live, err := liveSessions(p)
	if err != nil {
		return nil, err
	}
	var out []*vcs.Record
	for _, f := range files {
		rec, err := vcs.Load(f)
		if err != nil {
			return nil, err
		}
		if !slices.ContainsFunc(live, func(s liveSession) bool { return s.info.ID == rec.Session }) {
			out = append(out, rec)
		}
	}
	slices.SortFunc(out, func(a, b *vcs.Record) int { return a.Started.Compare(b.Started) })
	return out, nil
}

// finishInterrupted runs the end step of sessions that ended without one,
// for example because girdle was killed.
func finishInterrupted(p config.Paths, w io.Writer) {
	recs, err := records(p)
	if err != nil {
		fmt.Fprintf(w, "girdle: %v\n", err)
		return
	}
	for _, rec := range recs {
		if rec.Finished {
			continue
		}
		fmt.Fprintf(w, "girdle: session %s ended without checking its repositories; checking them now\n", rec.Session)
		if err := session.FinishRecord(context.Background(), p, vcsTools(), rec, w); err != nil {
			fmt.Fprintf(w, "girdle: %v\n", err)
		}
	}
}

func cmdRestore(args []string, w io.Writer) error {
	if len(args) != 1 {
		return errors.New("restore: usage: girdle restore SESSION")
	}
	p, err := paths()
	if err != nil {
		return err
	}
	finishInterrupted(p, w)
	path := filepath.Join(p.Backups(), args[0]+".json")
	rec, err := vcs.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("restore: no record of session %s, or girdle clean removed it", args[0])
	}
	if err != nil {
		return err
	}
	if err := vcs.Restore(context.Background(), vcsTools(), rec, w); err != nil {
		return err
	}
	for i := range rec.Repos {
		rec.Repos[i].Moved, rec.Repos[i].MovedBookmarks = nil, nil
	}
	return rec.Save(path)
}

// cmdClean removes what sessions leave behind once it is safe: agent
// worktrees whose work is merged, and the refs that keep the start values of
// moved branches. With --caches PROFILE it removes a profile's caches.
func cmdClean(args []string, in io.Reader, w io.Writer) error {
	if len(args) == 2 && args[0] == "--caches" {
		return cleanCaches(args[1], w)
	}
	if len(args) != 0 {
		return errors.New("clean: usage: girdle clean [--caches PROFILE]")
	}
	p, err := paths()
	if err != nil {
		return err
	}
	finishInterrupted(p, w)
	recs, err := records(p)
	if err != nil {
		return err
	}
	ctx, t := context.Background(), vcsTools()
	type worktree struct {
		repo vcs.Repo
		dir  string
	}
	var merged []worktree
	var backups []*vcs.Record
	for _, rec := range recs {
		if !rec.Finished {
			continue
		}
		for _, r := range rec.Repos {
			for _, name := range r.AgentWorktrees {
				if dir, ok := vcs.Merged(ctx, t, r, name); ok {
					merged = append(merged, worktree{r, dir})
				}
			}
		}
		backups = append(backups, rec)
	}
	if len(merged) == 0 && len(backups) == 0 {
		fmt.Fprintln(w, "Nothing to clean.")
		return nil
	}
	for _, m := range merged {
		fmt.Fprintf(w, "worktree %s, merged into the default branch of %s\n", m.dir, m.repo.Path)
	}
	for _, rec := range backups {
		var moved []string
		for _, r := range rec.Repos {
			moved = append(moved, r.Moved...)
			moved = append(moved, r.MovedBookmarks...)
		}
		if len(moved) > 0 {
			fmt.Fprintf(w, "start values of session %s (%s): %s\n", rec.Session, rec.Started.Format("Jan 2 15:04"), strings.Join(moved, ", "))
		} else {
			fmt.Fprintf(w, "record of session %s (%s)\n", rec.Session, rec.Started.Format("Jan 2 15:04"))
		}
	}
	fmt.Fprint(w, "Remove these? [y/N] ")
	answer, _ := bufio.NewReader(in).ReadString('\n')
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "y") {
		return nil
	}
	var errs []error
	for _, m := range merged {
		if err := vcs.RemoveWorktree(ctx, t, m.repo, m.dir); err != nil {
			errs = append(errs, err)
		}
	}
	for _, rec := range backups {
		if err := vcs.DropBackups(ctx, t, rec); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := os.Remove(filepath.Join(p.Backups(), rec.Session+".json")); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
