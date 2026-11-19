package vcs

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Tools are the host programs this package runs. An empty JJ skips jj
// bookmarks.
type Tools struct {
	Git string
	JJ  string
}

type Record struct {
	Session  string    `json:"session"`
	Profile  string    `json:"profile"`
	Started  time.Time `json:"started"`
	Finished bool      `json:"finished"`
	Repos    []Repo    `json:"repos"`
	// Writable are the host paths the session could write, where the agent
	// could have put a worktree's checkout.
	Writable []string `json:"writable"`
	// Owner is the doriath process that runs the session. Another start
	// must not finish the record while that process runs.
	Owner Owner `json:"owner,omitzero"`
}

// Owner names a process by its id and its start time, which together stay
// unique when the system reuses the id.
type Owner struct {
	PID   int    `json:"pid"`
	Start uint64 `json:"start"`
}

type Repo struct {
	Path           string            `json:"path"`
	GitDir         string            `json:"git_dir"`
	Branches       map[string]string `json:"branches"`
	Bookmarks      map[string]string `json:"bookmarks,omitempty"`
	Worktrees      []string          `json:"worktrees"`
	Moved          []string          `json:"moved,omitempty"`
	MovedBookmarks []string          `json:"moved_bookmarks,omitempty"`
	AgentWorktrees []string          `json:"agent_worktrees,omitempty"`
	Links          map[string]string `json:"links,omitempty"`
}

func BackupRef(session, branch string) string {
	return "refs/doriath/" + session + "/" + strings.TrimPrefix(branch, "refs/heads/")
}

func Store(repo string) string {
	if info, err := os.Stat(filepath.Join(repo, ".git")); err == nil && info.IsDir() {
		return filepath.Join(repo, ".git")
	}
	if git, _ := Linked(repo); git != "" {
		return git
	}
	if info, err := os.Lstat(filepath.Join(repo, ".jj", "repo", "store", "git")); err == nil && info.IsDir() {
		return filepath.Join(repo, ".jj", "repo", "store", "git")
	}
	return ""
}

func Linked(repo string) (git, jj string) {
	if data, err := os.ReadFile(filepath.Join(repo, ".git")); err == nil {
		if admin, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir: "); ok {
			admin = resolve(repo, admin)
			if common, err := os.ReadFile(filepath.Join(admin, "commondir")); err == nil {
				git = resolve(admin, strings.TrimSpace(string(common)))
			}
		}
	}
	if info, err := os.Lstat(filepath.Join(repo, ".jj", "repo")); err == nil && info.Mode().IsRegular() {
		if data, err := os.ReadFile(filepath.Join(repo, ".jj", "repo")); err == nil {
			jj = resolve(filepath.Join(repo, ".jj"), strings.TrimSpace(string(data)))
		}
	}
	return git, jj
}

func Root(repo string) string {
	switch {
	case filepath.Base(repo) == ".git":
		return filepath.Dir(repo)
	case filepath.Base(repo) == "repo" && filepath.Base(filepath.Dir(repo)) == ".jj":
		return filepath.Dir(filepath.Dir(repo))
	}
	if git, jj := Linked(repo); git != "" {
		return filepath.Dir(git)
	} else if jj != "" {
		return filepath.Dir(filepath.Dir(jj))
	}
	return repo
}

func guardAlternates(gitDir string, depth int) error {
	info := filepath.Join(gitDir, "objects", "info")
	if err := os.MkdirAll(info, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(info, "alternates"), os.O_CREATE|os.O_WRONLY|unix.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if depth >= 4 {
		return nil
	}
	for _, name := range entries(filepath.Join(gitDir, "modules")) {
		if sub := filepath.Join(gitDir, "modules", name); isDir(sub) {
			if err := guardAlternates(sub, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func isDir(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

func resolve(base, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(base, path)
}

func hasJJ(repo string) bool {
	info, err := os.Stat(filepath.Join(repo, ".jj", "repo"))
	return err == nil && info.IsDir()
}

func colocated(repo string) bool {
	info, err := os.Stat(filepath.Join(repo, ".git"))
	return err == nil && info.IsDir() && hasJJ(repo)
}

// Prepare creates the store directories, lock files and settings that git
// and jj create on first use, because the agent cannot create them in a
// read-only control directory.
func Prepare(ctx context.Context, t Tools, repo string) error {
	if git := Store(repo); git != "" {
		for _, name := range []string{"worktrees", "logs", "refs"} {
			if err := os.MkdirAll(filepath.Join(git, name), 0o755); err != nil {
				return err
			}
		}
		if err := guardAlternates(git, 0); err != nil {
			return err
		}
	}
	return nil
}

// Start records the branches, bookmarks and worktrees of each repository,
// and hardlinks its objects under backup, so that a git gc in the session
// cannot drop what your branches point at.
func Start(ctx context.Context, t Tools, backup string, rec *Record, repos []string) error {
	seen := map[string]bool{}
	for _, path := range repos {
		git := Store(path)
		if git == "" || seen[git] {
			continue
		}
		seen[git] = true
		branches, err := refs(ctx, t, git)
		if err != nil {
			return fmt.Errorf("record the branches of %s: %w", path, err)
		}
		r := Repo{Path: path, GitDir: git, Branches: branches, Worktrees: listWorktrees(git), Links: storeLinks(git)}
		if hasJJ(path) && !colocated(path) && t.JJ != "" {
			if r.Bookmarks, err = bookmarks(ctx, t, path); err != nil {
				return fmt.Errorf("record the bookmarks of %s: %w", path, err)
			}
		}
		if err := mirror(filepath.Join(git, "objects"), filepath.Join(backup, fmt.Sprint(len(rec.Repos)), "objects")); err != nil {
			return fmt.Errorf("keep the objects of %s: %w", path, err)
		}
		if hasJJ(path) && !colocated(path) {
			if err := mirror(filepath.Join(path, ".jj", "repo", "store", "extra"), filepath.Join(backup, fmt.Sprint(len(rec.Repos)), "extra")); err != nil {
				return fmt.Errorf("keep the jj store of %s: %w", path, err)
			}
		}
		rec.Repos = append(rec.Repos, r)
		for _, sub := range submoduleStores(git, 1) {
			branches, err := refs(ctx, t, sub)
			if err != nil {
				return fmt.Errorf("record the branches of submodule %s: %w", sub, err)
			}
			if err := mirror(filepath.Join(sub, "objects"), filepath.Join(backup, fmt.Sprint(len(rec.Repos)), "objects")); err != nil {
				return fmt.Errorf("keep the objects of submodule %s: %w", sub, err)
			}
			rec.Repos = append(rec.Repos, Repo{Path: submoduleCheckout(sub), GitDir: sub, Branches: branches, Worktrees: listWorktrees(sub), Links: storeLinks(sub)})
		}
	}
	return nil
}

const MaxSubmoduleDepth = 4

func submoduleStores(gitDir string, depth int) []string {
	if depth > MaxSubmoduleDepth {
		return nil
	}
	var out []string
	for _, sub := range ModuleStores(filepath.Join(gitDir, "modules"), osDirs{}) {
		out = append(out, sub)
		out = append(out, submoduleStores(sub, depth+1)...)
	}
	return out
}

type Dirs interface {
	// Kind returns "dir", "file", "other" or "" when the path does not exist.
	Kind(path string) string
	Entries(dir string) []string
}

func ModuleStores(modules string, dirs Dirs) []string {
	return moduleStores(modules, dirs, 0)
}

func moduleStores(modules string, dirs Dirs, depth int) []string {
	if depth > maxModuleDepth {
		return nil
	}
	var out []string
	for _, name := range dirs.Entries(modules) {
		p := filepath.Join(modules, name)
		switch {
		case dirs.Kind(p) != "dir":
		case IsStore(p, dirs):
			out = append(out, p)
		default:
			out = append(out, moduleStores(p, dirs, depth+1)...)
		}
	}
	return out
}

func IsStore(dir string, dirs Dirs) bool {
	return dirs.Kind(filepath.Join(dir, "HEAD")) == "file" && dirs.Kind(filepath.Join(dir, "objects")) == "dir"
}

type osDirs struct{}

func (osDirs) Kind(p string) string {
	info, err := os.Lstat(p)
	switch {
	case err != nil:
		return ""
	case info.IsDir():
		return "dir"
	case info.Mode().IsRegular():
		return "file"
	}
	return "other"
}

func (osDirs) Entries(dir string) []string { return entries(dir) }

func submoduleCheckout(store string) string {
	data, err := os.ReadFile(filepath.Join(store, "config"))
	if err != nil {
		return store
	}
	for line := range strings.Lines(string(data)) {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "worktree") {
			return resolve(store, strings.TrimSpace(value))
		}
	}
	return store
}

// Finish runs when the session ends, or on the next start if doriath exited
// first. It brings back objects the session deleted, keeps the start value
// of each branch the agent moved under refs/doriath/<session>/, resets the
// repository pointer of the worktrees the agent added, and reports.
func Finish(ctx context.Context, t Tools, backup string, rec *Record, fixed, notices io.Writer, progress Progress) error {
	var errs []error
	known := map[string]string{}
	for i := range rec.Repos {
		rec.Repos[i].knownLinks(known)
	}
	for i := range rec.Repos {
		r := &rec.Repos[i]
		if _, err := os.Stat(r.GitDir); errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(notices, "%s is gone, so there is nothing to check in it\n", r.Path)
			continue
		}
		if top := topStore(rec, r.GitDir); top != "" && hasLinkBelow(top, r.GitDir, known) {
			fmt.Fprintf(notices, "the agent made the store %s a link to another folder, so doriath did not check %s\n", r.GitDir, r.Path)
			continue
		}
		removed, restored, err := fixStoreLinks(r.GitDir, r.Links)
		for _, note := range linkNotes(r.GitDir, removed, restored) {
			fmt.Fprintln(fixed, note)
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := unmirror(filepath.Join(backup, fmt.Sprint(i), "objects"), filepath.Join(r.GitDir, "objects")); err != nil {
			errs = append(errs, fmt.Errorf("bring back the objects of %s: %w", r.Path, err))
			continue
		}
		if err := unmirror(filepath.Join(backup, fmt.Sprint(i), "extra"), filepath.Join(r.Path, ".jj", "repo", "store", "extra")); err != nil {
			errs = append(errs, fmt.Errorf("bring back the jj store of %s: %w", r.Path, err))
			continue
		}
		var packs Progress
		if progress != nil {
			packs = func(c PackCheck) {
				c.Repo = r.Path
				progress(c)
			}
		}
		for _, bad := range dropForgedObjects(ctx, t, r.GitDir, filepath.Join(backup, fmt.Sprint(i), "objects"), packs) {
			fmt.Fprintf(fixed, "removed %s from %s: the agent wrote it and git could not verify it\n", bad, r.Path)
		}
		now, err := refs(ctx, t, r.GitDir)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		r.Moved = nil
		for _, name := range slices.Sorted(maps.Keys(r.Branches)) {
			if now[name] == r.Branches[name] {
				continue
			}
			if _, err := runStore(ctx, t, r.GitDir, "update-ref", BackupRef(rec.Session, name), r.Branches[name]); err != nil {
				errs = append(errs, err)
				continue
			}
			r.Moved = append(r.Moved, name)
		}
		if len(r.Bookmarks) > 0 && t.JJ != "" {
			if now, err := bookmarks(ctx, t, r.Path); err == nil {
				r.MovedBookmarks = nil
				for _, name := range slices.Sorted(maps.Keys(r.Bookmarks)) {
					if now[name] != r.Bookmarks[name] {
						r.MovedBookmarks = append(r.MovedBookmarks, name)
					}
				}
			}
		}
		for _, bad := range dropForgedLFS(filepath.Join(r.GitDir, "lfs", "objects"), rec.Started) {
			fmt.Fprintf(fixed, "removed LFS object %s from %s: its content does not match its name\n", bad, r.Path)
		}
		r.AgentWorktrees = nil
		for _, name := range listWorktrees(r.GitDir) {
			if slices.Contains(r.Worktrees, name) {
				continue
			}
			r.AgentWorktrees = append(r.AgentWorktrees, name)
			if err := repairWorktree(filepath.Join(r.GitDir, "worktrees", name), rec, r.Path, fixed, false); err != nil {
				errs = append(errs, err)
			}
		}
		if err := setAsideAgentState(r.GitDir, rec, fixed); err != nil {
			errs = append(errs, err)
		}
		report(notices, rec.Session, r)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	rec.Finished = true
	return removeTree(backup)
}

var agentState = []string{"rebase-merge", "rebase-apply", "sequencer", "rr-cache"}

func setAsideAgentState(gitDir string, rec *Record, w io.Writer) error {
	var errs []error
	aside := func(p, what string) {
		to := p + ".doriath-" + rec.Session
		if err := os.Rename(p, to); err != nil {
			errs = append(errs, err)
			return
		}
		fmt.Fprintf(w, "moved %s the agent left in %s aside, to %s\n", what, gitDir, to)
	}
	for _, name := range agentState {
		if p := filepath.Join(gitDir, name); isDir(p) && changedWithin(p, rec.Started) {
			aside(p, name)
		}
	}
	for _, sub := range submoduleStores(gitDir, 1) {
		known := slices.ContainsFunc(rec.Repos, func(r Repo) bool { return r.GitDir == sub })
		if !known && changedSince(sub, rec.Started) {
			aside(sub, "a submodule store")
		}
	}
	return errors.Join(errs...)
}

func changedWithin(dir string, since time.Time) bool {
	changed := false
	_ = filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err == nil && changedSince(p, since) {
			changed = true
			return filepath.SkipAll
		}
		return nil
	})
	return changed
}

func report(w io.Writer, session string, r *Repo) {
	var moved []string
	for _, b := range r.Moved {
		moved = append(moved, strings.TrimPrefix(b, "refs/heads/"))
	}
	moved = append(moved, r.MovedBookmarks...)
	if len(moved) > 0 {
		fmt.Fprintf(w, "%s moved in %s while the session ran, by the agent or another program; put back with: doriath restore %s %s\n", strings.Join(moved, ", "), r.Path, session, strings.Join(moved, " "))
	}
	if len(r.AgentWorktrees) > 0 {
		fmt.Fprintf(w, "the session added worktrees %s in %s; doriath clean removes them once merged\n", strings.Join(r.AgentWorktrees, ", "), r.Path)
	}
}

// Restore puts the branches and bookmarks the session moved back where they
// were when it started. Branches the agent created stay.
func Restore(ctx context.Context, t Tools, rec *Record, w io.Writer) error {
	var errs []error
	for _, r := range rec.Repos {
		for _, name := range r.Moved {
			if _, err := runStore(ctx, t, r.GitDir, "update-ref", name, r.Branches[name]); err != nil {
				errs = append(errs, err)
				continue
			}
			if _, err := runStore(ctx, t, r.GitDir, "update-ref", "-d", BackupRef(rec.Session, name)); err != nil {
				errs = append(errs, err)
				continue
			}
			fmt.Fprintf(w, "%s: %s is back at %s\n", r.Path, strings.TrimPrefix(name, "refs/heads/"), short(r.Branches[name]))
		}
		for _, name := range r.MovedBookmarks {
			if t.JJ == "" {
				errs = append(errs, fmt.Errorf("%s: restoring bookmark %s needs jj", r.Path, name))
				continue
			}
			if _, err := run(ctx, t.JJ, "--repository", r.Path, "--ignore-working-copy", "bookmark", "set", name, "--allow-backwards", "-r", r.Bookmarks[name]); err != nil {
				errs = append(errs, err)
				continue
			}
			fmt.Fprintf(w, "%s: bookmark %s is back at %s\n", r.Path, name, short(r.Bookmarks[name]))
		}
	}
	return errors.Join(errs...)
}

func (rec *Record) Only(names []string) (unknown []string) {
	matched := map[string]bool{}
	keep := func(moved []string, short func(string) string) []string {
		var out []string
		for _, m := range moved {
			if slices.Contains(names, short(m)) {
				out = append(out, m)
				matched[short(m)] = true
			}
		}
		return out
	}
	branch := func(n string) string { return strings.TrimPrefix(n, "refs/heads/") }
	same := func(n string) string { return n }
	for i := range rec.Repos {
		rec.Repos[i].Moved = keep(rec.Repos[i].Moved, branch)
		rec.Repos[i].MovedBookmarks = keep(rec.Repos[i].MovedBookmarks, same)
	}
	for _, n := range names {
		if !matched[n] {
			unknown = append(unknown, n)
		}
	}
	return unknown
}

func KeepBackups(ctx context.Context, t Tools, recs ...*Record) error {
	var errs []error
	stores := map[string]map[string]string{}
	for _, rec := range recs {
		for _, r := range rec.Repos {
			if len(r.Moved) == 0 || !isDir(r.GitDir) {
				continue
			}
			now, ok := stores[r.GitDir]
			if !ok {
				var err error
				if now, err = backupRefs(ctx, t, r.GitDir); err != nil {
					errs = append(errs, err)
					continue
				}
				stores[r.GitDir] = now
			}
			for _, name := range r.Moved {
				ref := BackupRef(rec.Session, name)
				if now[ref] == r.Branches[name] {
					continue
				}
				if _, err := runStore(ctx, t, r.GitDir, "update-ref", ref, r.Branches[name]); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	return errors.Join(errs...)
}

func backupRefs(ctx context.Context, t Tools, gitDir string) (map[string]string, error) {
	out, err := runStore(ctx, t, gitDir, "for-each-ref", "--format=%(objectname) %(refname)", "refs/doriath/")
	if err != nil {
		return nil, err
	}
	refs := map[string]string{}
	for line := range strings.Lines(out) {
		if id, name, ok := strings.Cut(strings.TrimSpace(line), " "); ok {
			refs[name] = id
		}
	}
	return refs, nil
}

func DropBackups(ctx context.Context, t Tools, rec *Record) error {
	var errs []error
	for _, r := range rec.Repos {
		for _, name := range r.Moved {
			if _, err := runStore(ctx, t, r.GitDir, "update-ref", "-d", BackupRef(rec.Session, name)); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// Merged reports whether an agent worktree is clean and its HEAD is already
// in the repository's default branch, so removing it loses nothing.
func Merged(ctx context.Context, t Tools, r Repo, worktree string) (dir string, ok bool) {
	gitdir, err := os.ReadFile(filepath.Join(r.GitDir, "worktrees", worktree, "gitdir"))
	if err != nil {
		return "", false
	}
	path := strings.TrimSpace(string(gitdir))
	if !filepath.IsAbs(path) {
		path = filepath.Join(r.GitDir, "worktrees", worktree, path)
	}
	dir = filepath.Dir(path)
	admin := filepath.Join(r.GitDir, "worktrees", worktree)
	if !pointsTo(dir, admin) {
		return dir, false
	}
	status, err := run(ctx, t.Git, "-C", dir, "status", "--porcelain")
	if err != nil || strings.TrimSpace(status) != "" {
		return dir, false
	}
	head, err := run(ctx, t.Git, "-C", dir, "rev-parse", "HEAD")
	if err != nil {
		return dir, false
	}
	base := defaultBranch(ctx, t, r.GitDir)
	if base == "" {
		return dir, false
	}
	_, err = runStore(ctx, t, r.GitDir, "merge-base", "--is-ancestor", strings.TrimSpace(head), base)
	return dir, err == nil
}

func RemoveWorktree(ctx context.Context, t Tools, r Repo, dir string) error {
	branch, _ := run(ctx, t.Git, "-C", dir, "symbolic-ref", "--quiet", "--short", "HEAD")
	if _, err := runStore(ctx, t, r.GitDir, "worktree", "remove", dir); err != nil {
		return err
	}
	if b := strings.TrimSpace(branch); b != "" {
		if _, err := runStore(ctx, t, r.GitDir, "branch", "-d", b); err != nil {
			return err
		}
	}
	return nil
}

func defaultBranch(ctx context.Context, t Tools, gitDir string) string {
	if ref, err := runStore(ctx, t, gitDir, "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"); err == nil {
		return strings.TrimSpace(ref)
	}
	for _, name := range []string{"refs/heads/main", "refs/heads/master"} {
		if _, err := runStore(ctx, t, gitDir, "rev-parse", "--verify", "--quiet", name); err == nil {
			return name
		}
	}
	return ""
}

func refs(ctx context.Context, t Tools, gitDir string) (map[string]string, error) {
	out, err := runStore(ctx, t, gitDir, "for-each-ref", "--format=%(objectname) %(refname)", "refs/heads")
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if id, name, ok := strings.Cut(line, " "); ok {
			m[name] = id
		}
	}
	return m, nil
}

// JJSecureConfig returns the directory of a repository's secure config,
// which jj 0.46 keeps under your own config directory, named by the
// repository's config-id. It has your jj create both when the repository
// has none: jj creates them only when it migrates a legacy
// .jj/repo/config.toml, and the jail's read-only placeholder of that file
// looks like one, which jj in the jail then fails to replace with a link.
// An empty legacy file is a placeholder of an earlier session and goes
// first, so that jj creates the id without a migration; one with content
// is your own config, and stays for jj to migrate. The jail needs the
// directory to read the config-id it points at: without it, jj in the jail
// tries to create both again.
func JJSecureConfig(ctx context.Context, t Tools, jjRepo string) (string, error) {
	if t.JJ == "" {
		return "", nil
	}
	legacy := filepath.Join(jjRepo, "config.toml")
	if _, err := os.Lstat(filepath.Join(jjRepo, "config-id")); errors.Is(err, fs.ErrNotExist) {
		info, err := os.Lstat(legacy)
		switch {
		case err == nil && info.Mode().IsRegular() && info.Size() == 0:
			if err := os.Remove(legacy); err != nil {
				return "", err
			}
		case err == nil:
			return "", nil
		case !errors.Is(err, fs.ErrNotExist):
			return "", err
		}
	}
	repo := filepath.Dir(filepath.Dir(jjRepo))
	out, err := runIn(ctx, repo, t.JJ, "--repository", repo, "--ignore-working-copy", "config", "path", "--repo")
	if err != nil {
		return "", err
	}
	return filepath.Dir(strings.TrimSpace(out)), nil
}

func bookmarks(ctx context.Context, t Tools, repo string) (map[string]string, error) {
	out, err := run(ctx, t.JJ, "--repository", repo, "--ignore-working-copy", "--color", "never", "bookmark", "list", "-T", `if(!remote && normal_target, name ++ " " ++ normal_target.commit_id() ++ "\n")`)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if name, id, ok := strings.Cut(line, " "); ok {
			m[name] = id
		}
	}
	return m, nil
}

func dropForgedLFS(dir string, since time.Time) []string {
	var forged []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !changedSince(p, since) {
			return nil
		}
		if d.Type().IsRegular() {
			if sum, err := sha256File(p); err == nil && sum == d.Name() {
				return nil
			}
		}
		if os.Remove(p) == nil {
			forged = append(forged, d.Name())
		}
		return nil
	})
	return forged
}

func changedSince(p string, since time.Time) bool {
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		return true
	}
	return !time.Unix(st.Ctim.Unix()).Before(since)
}

func sha256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func repairWorktree(admin string, rec *Record, repo string, w io.Writer, live bool) error {
	name := filepath.Base(admin)
	gitDir := filepath.Dir(filepath.Dir(admin))
	worktrees, err := openDirBeneath(gitDir, "worktrees")
	if err != nil {
		return nil
	}
	defer func() { _ = unix.Close(worktrees) }()
	var st unix.Stat_t
	if err := unix.Fstatat(worktrees, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		if err := unix.Unlinkat(worktrees, name, 0); err != nil {
			return err
		}
		fmt.Fprintf(w, "removed worktree %s of %s, which the agent made a link to another directory\n", name, repo)
		return nil
	}
	adminFD, err := unix.Openat(worktrees, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(adminFD) }()
	data, readErr := readAt(adminFD, "gitdir")
	if live && (readErr != nil || removing(admin, data)) {
		return nil
	}
	if fixed, err := resetCommondir(adminFD); err != nil {
		return err
	} else if fixed {
		fmt.Fprintf(w, "the agent pointed worktree %s of %s at another repository; doriath pointed it back\n", name, repo)
	}
	if neutralized, err := neutralizeWorktreeConfig(adminFD); err != nil {
		return err
	} else if neutralized {
		fmt.Fprintf(w, "emptied the config the agent wrote for worktree %s of %s\n", name, repo)
	}
	if readErr != nil {
		return nil
	}
	checkout := filepath.Dir(resolve(admin, strings.TrimSpace(string(data))))
	writableRoot := func(p string) (string, bool) {
		i := slices.IndexFunc(rec.Writable, func(root string) bool { return within(p, root) })
		if i < 0 {
			return "", false
		}
		return rec.Writable[i], true
	}
	real, err := filepath.EvalSymlinks(checkout)
	if err != nil {
		real = checkout
	}
	root, ok := writableRoot(real)
	if _, inside := writableRoot(checkout); !ok || !inside {
		fmt.Fprintf(w, "worktree %s of %s says it is at %s, where the session could not write; doriath left it alone, so check it before you use it\n", name, repo, checkout)
		return nil
	}
	if pointsTo(checkout, admin) {
		return nil
	}
	rel, _ := filepath.Rel(root, real)
	dir, err := openBeneath(root, rel)
	if live && errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("open worktree %s: %w", checkout, err)
	}
	defer func() { _ = unix.Close(dir) }()
	err = unix.Fstatat(dir, ".git", &st, unix.AT_SYMLINK_NOFOLLOW)
	if live && errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err == nil && st.Mode&unix.S_IFMT != unix.S_IFREG {
		aside := ".git.doriath-" + rec.Session
		if err := unix.Renameat(dir, ".git", dir, aside); err != nil {
			return err
		}
		fmt.Fprintf(w, "moved the .git the agent put in worktree %s aside, to %s\n", checkout, filepath.Join(real, aside))
	} else if !errors.Is(err, unix.ENOENT) && err != nil {
		return err
	}
	if err := replaceAt(dir, ".git", []byte("gitdir: "+admin+"\n")); err != nil {
		return err
	}
	fmt.Fprintf(w, "pointed worktree %s back at %s\n", checkout, repo)
	return nil
}

// neutralizeWorktreeConfig empties a config.worktree in place rather than
// removing it: an empty one may be the placeholder another session binds
// read-only into its jail, and removing it would detach that mount. A file
// with other links is removed instead, so that emptying it does not reach
// the agent's other name for it.
func neutralizeWorktreeConfig(admin int) (bool, error) {
	const name = "config.worktree"
	var st unix.Stat_t
	if err := unix.Fstatat(admin, name, &st, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if !singleLinkFile(&st) {
		return true, takeAway(admin, name)
	}
	if st.Size == 0 {
		return false, nil
	}
	fd, err := unix.Openat(admin, name, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return true, takeAway(admin, name)
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if err := unix.Fstat(fd, &st); err != nil || !singleLinkFile(&st) {
		return true, takeAway(admin, name)
	}
	return true, f.Truncate(0)
}

func singleLinkFile(st *unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink == 1
}

func removing(admin string, gitdir []byte) bool {
	_, err := os.Stat(filepath.Dir(resolve(admin, strings.TrimSpace(string(gitdir)))))
	return errors.Is(err, fs.ErrNotExist)
}

func within(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

func resetCommondir(admin int) (bool, error) {
	data, err := readAt(admin, Commondir)
	if err == nil && strings.TrimSpace(string(data)) == "../.." {
		return false, nil
	}
	if err := takeAway(admin, Commondir); err != nil && !errors.Is(err, unix.ENOENT) {
		return false, err
	}
	return true, replaceAt(admin, Commondir, []byte("../..\n"))
}

func openBeneath(root, rel string) (int, error) {
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer func() { _ = unix.Close(rootFD) }()
	return unix.Openat2(rootFD, rel, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
}

func replaceAt(dir int, name string, data []byte) error {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := name + ".doriath-" + hex.EncodeToString(suffix[:])
	fd, err := unix.Openat(dir, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(dir, tmp, dir, name)
	}
	if err != nil {
		_ = unix.Unlinkat(dir, tmp, 0)
	}
	return err
}

var gitEnv = []string{"GIT_CONFIG_PARAMETERS='core.hooksPath=/dev/null' 'core.fsmonitor=false'"}

func runStore(ctx context.Context, t Tools, gitDir string, args ...string) (string, error) {
	return run(ctx, t.Git, append([]string{"--git-dir", gitDir, "--work-tree", gitDir}, args...)...)
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	return runIn(ctx, "", name, args...)
}

// runIn runs a command in dir. jj also reads the repository it starts in,
// whatever --repository names.
func runIn(ctx context.Context, dir, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), gitEnv...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", filepath.Base(name), strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

func mirror(src, dst string) error {
	return walkParallel(src, func(p string, d fs.DirEntry, err error) (func() error, error) {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return nil, os.MkdirAll(target, 0o700)
		}
		if !d.Type().IsRegular() || strings.HasSuffix(p, ".lock") {
			return nil, nil
		}
		put := copyFile
		if filepath.Dir(rel) == "pack" {
			put = linkOrCopy
		}
		return func() error {
			if err := put(p, target); !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			return nil
		}, nil
	})
}

func unmirror(src, dst string) error {
	return walkParallel(src, func(p string, d fs.DirEntry, err error) (func() error, error) {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return nil, realDir(target, rel == ".")
		}
		return func() error {
			if _, err := os.Lstat(target); err == nil {
				if filepath.Dir(rel) == "pack" || sameContent(p, target) {
					return nil
				}
				if err := os.Remove(target); err != nil {
					return err
				}
			}
			return linkOrCopy(p, target)
		}, nil
	})
}

func realDir(dir string, top bool) error {
	info, err := os.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return os.MkdirAll(dir, 0o755)
	case err != nil:
		return err
	case info.IsDir():
		return nil
	case top:
		return fmt.Errorf("%s is not a directory", dir)
	}
	if err := os.Remove(dir); err != nil {
		return err
	}
	return os.Mkdir(dir, 0o755)
}

func sameContent(a, b string) bool {
	x, err := os.ReadFile(a)
	if err != nil {
		return false
	}
	y, err := os.ReadFile(b)
	return err == nil && bytes.Equal(x, y)
}

func linkOrCopy(src, dst string) error {
	if err := os.Link(src, dst); err == nil || errors.Is(err, fs.ErrExist) {
		return nil
	}
	return copyFile(src, dst)
}

func copyFile(src, dst string) error {
	in, err := os.OpenFile(src, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func entries(dir string) []string {
	es, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	return names
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func Load(path string) (*Record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &r, nil
}

// LoadAll loads the records at paths, in the same order. A record that
// does not load is nil, and its error is in errs.
func LoadAll(paths []string) (recs []*Record, errs []error) {
	recs, errs = make([]*Record, len(paths)), make([]error, len(paths))
	next := make(chan int)
	var wg sync.WaitGroup
	for range fileWorkers {
		wg.Go(func() {
			for i := range next {
				recs[i], errs[i] = Load(paths[i])
			}
		})
	}
	for i := range paths {
		next <- i
	}
	close(next)
	wg.Wait()
	return recs, errs
}

func (r *Record) Save(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func pointsTo(checkout, admin string) bool {
	data, err := os.ReadFile(filepath.Join(checkout, ".git"))
	if err != nil {
		return false
	}
	target, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir: ")
	return ok && filepath.Clean(resolve(checkout, target)) == filepath.Clean(admin)
}

func topStore(rec *Record, gitDir string) string {
	top := ""
	for _, o := range rec.Repos {
		if strings.HasPrefix(gitDir, o.GitDir+"/modules/") && (top == "" || len(o.GitDir) < len(top)) {
			top = o.GitDir
		}
	}
	return top
}
