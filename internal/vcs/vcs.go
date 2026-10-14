// Package vcs keeps your branches recoverable while an agent writes to a
// repository's store: it records them when a session starts, keeps their
// objects alive, and puts back what the agent moved when you ask.
package vcs

import (
	"bytes"
	"context"
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
	"time"
)

// Tools are the host programs this package runs. An empty JJ skips jj
// bookmarks.
type Tools struct {
	Git string
	JJ  string
}

// Record is what a session keeps about the repositories it touched, in
// <dir>/<session>.json, until girdle clean removes it.
type Record struct {
	Session  string    `json:"session"`
	Profile  string    `json:"profile"`
	Started  time.Time `json:"started"`
	Finished bool      `json:"finished"`
	Repos    []Repo    `json:"repos"`
}

type Repo struct {
	Path string `json:"path"`
	// GitDir is the git store: the repository's .git, or jj's own store.
	GitDir    string            `json:"git_dir"`
	Branches  map[string]string `json:"branches"`
	Bookmarks map[string]string `json:"bookmarks,omitempty"`
	Worktrees []string          `json:"worktrees"`
	// Moved lists the branches and bookmarks that the session changed or
	// deleted, filled in when it ends.
	Moved          []string `json:"moved,omitempty"`
	MovedBookmarks []string `json:"moved_bookmarks,omitempty"`
	// AgentWorktrees are the worktrees the session added.
	AgentWorktrees []string `json:"agent_worktrees,omitempty"`
}

// BackupRef is where a branch's start value is kept when the agent moved it.
func BackupRef(session, branch string) string {
	return "refs/girdle/" + session + "/" + strings.TrimPrefix(branch, "refs/heads/")
}

// Store finds the git store of a repository: its .git directory, the main
// repository's for a linked worktree, or the git directory inside jj's
// store when jj is not colocated with git.
func Store(repo string) string {
	if info, err := os.Stat(filepath.Join(repo, ".git")); err == nil && info.IsDir() {
		return filepath.Join(repo, ".git")
	}
	if git, _ := Linked(repo); git != "" {
		return git
	}
	if info, err := os.Stat(filepath.Join(repo, ".jj", "repo", "store", "git")); err == nil && info.IsDir() {
		return filepath.Join(repo, ".jj", "repo", "store", "git")
	}
	return ""
}

// Linked returns the main repository's git directory and jj repository
// when repo is a linked git worktree or a secondary jj workspace, whose
// .git and .jj/repo are files that point there.
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

// Root returns the root of the main repository that repo belongs to: repo
// itself, or the main checkout of a linked worktree or secondary workspace,
// or the repository whose store repo is.
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
// read-only control directory. It returns notes on what it changed.
func Prepare(ctx context.Context, t Tools, repo string, jjLocks []string) ([]string, error) {
	if git := Store(repo); git != "" {
		for _, name := range []string{"worktrees", "logs", "refs"} {
			if err := os.MkdirAll(filepath.Join(git, name), 0o755); err != nil {
				return nil, err
			}
		}
	}
	if !hasJJ(repo) {
		return nil, nil
	}
	var notes []string
	if colocated(repo) {
		git := filepath.Join(repo, ".git")
		if on, _ := run(ctx, t.Git, "--git-dir", git, "config", "--bool", "extensions.relativeWorktrees"); strings.TrimSpace(on) != "true" {
			for _, kv := range [][2]string{{"core.repositoryformatversion", "1"}, {"extensions.relativeWorktrees", "true"}} {
				if _, err := run(ctx, t.Git, "--git-dir", git, "config", kv[0], kv[1]); err != nil {
					return nil, err
				}
			}
			notes = append(notes, fmt.Sprintf("girdle turned on git's relativeWorktrees extension in %s, as jj does on its first workspace, because the jail cannot write .git/config", repo))
		}
	}
	for _, name := range jjLocks {
		f, err := os.OpenFile(filepath.Join(repo, ".jj", "repo", name), os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	}
	return notes, nil
}

// Start records the branches, bookmarks and worktrees of each repository,
// and hardlinks its objects under backup, so that a git gc in the session
// cannot drop what your branches point at.
func Start(ctx context.Context, t Tools, backup string, rec *Record, repos []string) error {
	seen := map[string]bool{}
	for i, path := range repos {
		git := Store(path)
		if git == "" || seen[git] {
			continue
		}
		seen[git] = true
		branches, err := refs(ctx, t, git)
		if err != nil {
			return fmt.Errorf("record the branches of %s: %w", path, err)
		}
		r := Repo{Path: path, GitDir: git, Branches: branches, Worktrees: entries(filepath.Join(git, "worktrees"))}
		if hasJJ(path) && !colocated(path) && t.JJ != "" {
			if r.Bookmarks, err = bookmarks(ctx, t, path); err != nil {
				return fmt.Errorf("record the bookmarks of %s: %w", path, err)
			}
		}
		if err := mirror(filepath.Join(git, "objects"), filepath.Join(backup, fmt.Sprint(i), "objects")); err != nil {
			return fmt.Errorf("keep the objects of %s: %w", path, err)
		}
		if hasJJ(path) && !colocated(path) {
			if err := mirror(filepath.Join(path, ".jj", "repo", "store", "extra"), filepath.Join(backup, fmt.Sprint(i), "extra")); err != nil {
				return fmt.Errorf("keep the jj store of %s: %w", path, err)
			}
		}
		rec.Repos = append(rec.Repos, r)
	}
	return nil
}

// Finish runs when the session ends, or on the next start if girdle exited
// first. It brings back objects the session deleted, keeps the start value
// of each branch the agent moved under refs/girdle/<session>/, resets the
// repository pointer of the worktrees the agent added, and reports.
func Finish(ctx context.Context, t Tools, backup string, rec *Record, w io.Writer) error {
	var errs []error
	for i := range rec.Repos {
		r := &rec.Repos[i]
		if err := unmirror(filepath.Join(backup, fmt.Sprint(i), "objects"), filepath.Join(r.GitDir, "objects")); err != nil {
			errs = append(errs, fmt.Errorf("bring back the objects of %s: %w", r.Path, err))
			continue
		}
		if err := unmirror(filepath.Join(backup, fmt.Sprint(i), "extra"), filepath.Join(r.Path, ".jj", "repo", "store", "extra")); err != nil {
			errs = append(errs, fmt.Errorf("bring back the jj store of %s: %w", r.Path, err))
			continue
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
			if _, err := run(ctx, t.Git, "--git-dir", r.GitDir, "update-ref", BackupRef(rec.Session, name), r.Branches[name]); err != nil {
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
			fmt.Fprintf(w, "girdle: removed LFS object %s from %s: its content does not match its name\n", bad, r.Path)
		}
		r.AgentWorktrees = nil
		for _, name := range entries(filepath.Join(r.GitDir, "worktrees")) {
			if slices.Contains(r.Worktrees, name) {
				continue
			}
			r.AgentWorktrees = append(r.AgentWorktrees, name)
			if fixed, err := resetCommondir(filepath.Join(r.GitDir, "worktrees", name)); err != nil {
				errs = append(errs, err)
			} else if fixed {
				fmt.Fprintf(w, "girdle: the agent pointed worktree %s of %s at another repository; girdle pointed it back\n", name, r.Path)
			}
		}
		report(w, rec.Session, r)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	rec.Finished = true
	return os.RemoveAll(backup)
}

func report(w io.Writer, session string, r *Repo) {
	var moved []string
	for _, b := range r.Moved {
		moved = append(moved, strings.TrimPrefix(b, "refs/heads/"))
	}
	moved = append(moved, r.MovedBookmarks...)
	if len(moved) > 0 {
		fmt.Fprintf(w, "girdle: the session moved or deleted %s in %s. `girdle restore %s` puts them back.\n", strings.Join(moved, ", "), r.Path, session)
	}
	if len(r.AgentWorktrees) > 0 {
		fmt.Fprintf(w, "girdle: the session added worktrees %s in %s. `girdle clean` removes them once merged.\n", strings.Join(r.AgentWorktrees, ", "), r.Path)
	}
}

// Restore puts the branches and bookmarks the session moved back where they
// were when it started. Branches the agent created stay.
func Restore(ctx context.Context, t Tools, rec *Record, w io.Writer) error {
	var errs []error
	for _, r := range rec.Repos {
		for _, name := range r.Moved {
			if _, err := run(ctx, t.Git, "--git-dir", r.GitDir, "update-ref", name, r.Branches[name]); err != nil {
				errs = append(errs, err)
				continue
			}
			if _, err := run(ctx, t.Git, "--git-dir", r.GitDir, "update-ref", "-d", BackupRef(rec.Session, name)); err != nil {
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

// DropBackups deletes the refs that keep the start values of moved branches.
func DropBackups(ctx context.Context, t Tools, rec *Record) error {
	var errs []error
	for _, r := range rec.Repos {
		for _, name := range r.Moved {
			if _, err := run(ctx, t.Git, "--git-dir", r.GitDir, "update-ref", "-d", BackupRef(rec.Session, name)); err != nil {
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
	_, err = run(ctx, t.Git, "--git-dir", r.GitDir, "merge-base", "--is-ancestor", strings.TrimSpace(head), base)
	return dir, err == nil
}

// RemoveWorktree removes an agent worktree and its branch, which Merged
// found already in the default branch.
func RemoveWorktree(ctx context.Context, t Tools, r Repo, dir string) error {
	branch, _ := run(ctx, t.Git, "-C", dir, "symbolic-ref", "--quiet", "--short", "HEAD")
	if _, err := run(ctx, t.Git, "--git-dir", r.GitDir, "worktree", "remove", dir); err != nil {
		return err
	}
	if b := strings.TrimSpace(branch); b != "" {
		if _, err := run(ctx, t.Git, "--git-dir", r.GitDir, "branch", "-d", b); err != nil {
			return err
		}
	}
	return nil
}

func defaultBranch(ctx context.Context, t Tools, gitDir string) string {
	if ref, err := run(ctx, t.Git, "--git-dir", gitDir, "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"); err == nil {
		return strings.TrimSpace(ref)
	}
	for _, name := range []string{"refs/heads/main", "refs/heads/master"} {
		if _, err := run(ctx, t.Git, "--git-dir", gitDir, "rev-parse", "--verify", "--quiet", name); err == nil {
			return name
		}
	}
	return ""
}

func refs(ctx context.Context, t Tools, gitDir string) (map[string]string, error) {
	out, err := run(ctx, t.Git, "--git-dir", gitDir, "for-each-ref", "--format=%(objectname) %(refname)", "refs/heads")
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

func bookmarks(ctx context.Context, t Tools, repo string) (map[string]string, error) {
	out, err := run(ctx, t.JJ, "--repository", repo, "--ignore-working-copy", "--color", "never", "bookmark", "list", "-T", `if(!remote, name ++ " " ++ normal_target.commit_id() ++ "\n")`)
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

// dropForgedLFS removes LFS objects written since the session started whose
// content does not hash to their name. Your checkout takes an LFS file's
// content from the object with its name, so a forged one would put the
// agent's content into your tree outside any commit.
func dropForgedLFS(dir string, since time.Time) []string {
	var forged []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.ModTime().Before(since) {
			return nil
		}
		if sum, err := sha256File(p); err == nil && sum != d.Name() {
			if os.Remove(p) == nil {
				forged = append(forged, d.Name())
			}
		}
		return nil
	})
	return forged
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

// resetCommondir points an agent worktree's admin directory back at its own
// repository. git in that worktree on the host follows commondir, and an
// agent could point it at a store whose config runs commands.
func resetCommondir(admin string) (bool, error) {
	p := filepath.Join(admin, "commondir")
	data, err := os.ReadFile(p)
	if err == nil && strings.TrimSpace(string(data)) == "../.." {
		return false, nil
	}
	if err := os.RemoveAll(p); err != nil {
		return false, err
	}
	return true, os.WriteFile(p, []byte("../..\n"), 0o644)
}

// gitEnv keeps the host's git away from what a session could have planted:
// hooks and the fsmonitor are user config, which the jail cannot write, but
// girdle's own commands need neither.
var gitEnv = []string{"GIT_CONFIG_PARAMETERS='core.hooksPath=/dev/null' 'core.fsmonitor=false'"}

func run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), gitEnv...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", filepath.Base(name), strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// mirror hardlinks every file under src into dst, copying when the two are
// on different filesystems.
func mirror(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		return linkOrCopy(p, target)
	})
}

// unmirror puts back every file of a mirror that is missing from dst.
func unmirror(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if _, err := os.Lstat(target); err == nil {
			return nil
		}
		return linkOrCopy(p, target)
	})
}

func linkOrCopy(src, dst string) error {
	if err := os.Link(src, dst); err == nil || errors.Is(err, fs.ErrExist) {
		return nil
	}
	in, err := os.Open(src)
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

// Load and Save keep records as JSON files.
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
