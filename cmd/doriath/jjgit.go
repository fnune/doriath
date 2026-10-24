package main

import (
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
)

// cmdJJGit runs in the jail as the git that jj runs. jj asks git for
// relative worktree paths, which git records by writing an extension into
// the repository's .git/config: the jail keeps that file read-only, and nix
// refuses a repository with the extension. The jail sees each repository
// where you do, so absolute paths serve both.
func cmdJJGit(args []string) error {
	git, err := exec.LookPath("git")
	if err != nil {
		return fmt.Errorf("jj-git: %w", err)
	}
	return syscall.Exec(git, append([]string{"git"}, jjGitArgs(args)...), os.Environ())
}

func jjGitArgs(args []string) []string {
	out := slices.Clone(args)
	for i := 1; i < len(out); i++ {
		if out[i-1] == "-c" && strings.EqualFold(out[i], "worktree.useRelativePaths=true") {
			out[i] = "worktree.useRelativePaths=false"
		}
	}
	return out
}
