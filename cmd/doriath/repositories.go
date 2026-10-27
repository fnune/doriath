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

	"github.com/fnune/doriath/internal/cli"
	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/session"
	"github.com/fnune/doriath/internal/term"
	"github.com/fnune/doriath/internal/vcs"
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
// for example because doriath was killed.
func finishInterrupted(p config.Paths, w io.Writer) {
	finishInterruptedOf(p, w, func(*vcs.Record) bool { return true })
}

func finishInterruptedOf(p config.Paths, w io.Writer, uses func(*vcs.Record) bool) []string {
	t := term.New(w)
	recs, err := records(p)
	if err != nil {
		t.Problem(err.Error())
		return nil
	}
	var notes []string
	for _, rec := range recs {
		if rec.Finished {
			continue
		}
		repos := strings.Join(repoPaths(rec), ", ")
		if !uses(rec) {
			notes = append(notes, fmt.Sprintf("session %s ended before doriath checked its repositories: %s. doriath checks a repository when a session uses it, or at %s", rec.Session, repos, cli.Code(cli.Line("clean"))))
			continue
		}
		t.Header("session "+rec.Session, "ended before doriath checked its repositories")
		t.Line(term.Info, "doriath checks the objects that the agent wrote in "+repos+" before they are used again")
		if err := session.FinishRecord(context.Background(), p, vcsTools(), rec, t.Lines(term.Action), t.Lines(term.Warn), w); err != nil {
			t.Line(term.Problem, err.Error())
		}
	}
	return notes
}

func usesStores(stores []string) func(*vcs.Record) bool {
	return func(rec *vcs.Record) bool {
		return slices.ContainsFunc(rec.Repos, func(r vcs.Repo) bool {
			return slices.Contains(stores, filepath.Clean(r.GitDir))
		})
	}
}

func repoPaths(rec *vcs.Record) []string {
	var out []string
	for _, r := range rec.Repos {
		out = append(out, r.Path)
	}
	return out
}

func cmdRestore(args []string, w io.Writer) error {
	if len(args) < 1 {
		return errors.New("restore: usage: doriath restore SESSION [BRANCH...]")
	}
	p, err := paths()
	if err != nil {
		return err
	}
	path := filepath.Join(p.Backups(), args[0]+".json")
	rec, err := vcs.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("restore: no record of session %s, or `doriath clean` removed it", args[0])
	}
	if err != nil {
		return err
	}
	var stores []string
	for _, r := range rec.Repos {
		stores = append(stores, filepath.Clean(r.GitDir))
	}
	finishInterruptedOf(p, w, usesStores(stores))
	if rec, err = vcs.Load(path); err != nil {
		return err
	}
	chosen, err := vcs.Load(path)
	if err != nil {
		return err
	}
	if names := args[1:]; len(names) > 0 {
		if unknown := chosen.Only(names); len(unknown) > 0 {
			return fmt.Errorf("restore: session %s moved no branch or bookmark named %s", args[0], strings.Join(unknown, ", "))
		}
	}
	if err := vcs.Restore(context.Background(), vcsTools(), chosen, w); err != nil {
		return err
	}
	for i := range rec.Repos {
		rec.Repos[i].Moved = slices.DeleteFunc(rec.Repos[i].Moved, func(n string) bool { return slices.Contains(chosen.Repos[i].Moved, n) })
		rec.Repos[i].MovedBookmarks = slices.DeleteFunc(rec.Repos[i].MovedBookmarks, func(n string) bool { return slices.Contains(chosen.Repos[i].MovedBookmarks, n) })
	}
	return rec.Save(path)
}

// cmdClean removes what sessions leave behind once it is safe: agent
// worktrees whose work is merged, and the refs that keep the start values of
// moved branches. With --caches PROFILE it removes a profile's caches.
func cmdClean(args []string, in io.Reader, w io.Writer) error {
	if len(args) != 0 {
		return errors.New("clean: usage: doriath clean (for the caches of a profile: `doriath profiles clean NAME`)")
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
