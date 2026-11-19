package vcs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

var inWorktreeConfig = []string{
	"-c", "core.fsmonitor=false",
	"-c", "core.hooksPath=/dev/null",
	"-c", "protocol.ext.allow=never",
	"-c", "diff.ignoreSubmodules=all",
	"-c", "status.submoduleSummary=false",
}

func inWorktree(ctx context.Context, t Tools, gitDir, dir string, args ...string) (string, error) {
	tree, err := runStore(ctx, t, gitDir, "hash-object", "-t", "tree", "--stdin")
	if err != nil {
		return "", err
	}
	full := append(append([]string{"-C", dir}, inWorktreeConfig...), args...)
	return runWith(ctx, []string{"GIT_ATTR_SOURCE=" + strings.TrimSpace(tree)}, "", t.Git, full...)
}

func gitlinkPaths(ctx context.Context, t Tools, gitDir string) ([]string, error) {
	out, err := runStore(ctx, t, gitDir, "ls-files", "--stage", "-z")
	if err != nil {
		return nil, err
	}
	return gitlinksIn(out), nil
}

func gitlinksIn(listing string) []string {
	var paths []string
	for rec := range strings.SplitSeq(listing, "\x00") {
		if rest, ok := strings.CutPrefix(rec, "160000 "); ok {
			if _, path, ok := strings.Cut(rest, "\t"); ok {
				paths = append(paths, path)
			}
		}
	}
	return paths
}

func nestedGits(ctx context.Context, t Tools, gitDir, checkout string) map[string]string {
	paths, err := gitlinkPaths(ctx, t, gitDir)
	if err != nil || len(paths) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, p := range paths {
		out[p] = nestedGit(checkout, p)
	}
	return out
}

func nestedGit(checkout, path string) string {
	dir, err := openBeneath(checkout, path)
	if err != nil {
		return ""
	}
	defer func() { _ = unix.Close(dir) }()
	var st unix.Stat_t
	if err := unix.Fstatat(dir, ".git", &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return ""
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		return fmt.Sprintf("dir:%d:%d", st.Dev, st.Ino)
	case unix.S_IFREG:
		data, _ := readAt(dir, ".git")
		return "file:" + strings.TrimSpace(string(data))
	}
	return "other"
}

func setAsideNestedGits(ctx context.Context, t Tools, r *Repo, rec *Record, w io.Writer) error {
	if r.Path == r.GitDir || !isDir(r.Path) {
		return nil
	}
	paths, err := gitlinkPaths(ctx, t, r.GitDir)
	if err != nil {
		return err
	}
	var errs []error
	for _, p := range paths {
		now := nestedGit(r.Path, p)
		if now == "" || now == r.Gitlinks[p] {
			continue
		}
		to, err := moveNestedGit(r.Path, p, rec.Session)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		fmt.Fprintf(w, "moved the repository that the agent put at %s in %s aside, to %s: git on your machine would run its config. A submodule that the agent adds is set aside too; add it yourself if you want it\n", p, r.Path, to)
	}
	return errors.Join(errs...)
}

func moveNestedGit(checkout, path, session string) (string, error) {
	dir, err := openBeneath(checkout, path)
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(dir) }()
	aside := ".git.doriath-" + session
	for i := 1; ; i++ {
		err := unix.Renameat2(dir, ".git", dir, aside, unix.RENAME_NOREPLACE)
		if err == nil {
			return filepath.Join(checkout, path, aside), nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", err
		}
		aside = ".git.doriath-" + session + "." + strconv.Itoa(i)
	}
}
