package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/fnune/doriath/internal/githubapp"
	"github.com/fnune/doriath/internal/profile"
)

// appMinter mints GitHub App tokens for the repository that holds dir.
func appMinter(dir string) githubapp.Minter {
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	return githubapp.Minter{Repository: profile.FindRepository(dir, exists), Remotes: gitRemoteURLs}
}

// gitRemoteURLs lists the URLs of the remotes of a repository, the origin
// first. Reading the config of git runs no program of the repository.
func gitRemoteURLs(ctx context.Context, dir string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "config", "--get-regexp", `^remote\..*\.url$`)
	cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0")
	out, err := cmd.Output()
	var exit *exec.ExitError
	noRemotes := errors.As(err, &exit) && exit.ExitCode() == 1
	if err != nil && !noRemotes {
		return nil, err
	}
	var urls []string
	scan := bufio.NewScanner(bytes.NewReader(out))
	for scan.Scan() {
		key, url, ok := strings.Cut(scan.Text(), " ")
		if !ok {
			continue
		}
		if key == "remote.origin.url" {
			urls = slices.Insert(urls, 0, url)
		} else {
			urls = append(urls, url)
		}
	}
	return urls, scan.Err()
}
