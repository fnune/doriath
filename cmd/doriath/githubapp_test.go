package main

import (
	"context"
	"os/exec"
	"slices"
	"testing"
)

func TestTheRemotesOfARepositoryComeOriginFirst(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	got, err := gitRemoteURLs(context.Background(), dir)
	if err != nil || len(got) != 0 {
		t.Fatalf("a repository without remotes = %v, %v", got, err)
	}
	git("remote", "add", "mirror", "https://example.com/mirror.git")
	git("remote", "add", "origin", "git@github.com:fnune/doriath.git")
	got, err = gitRemoteURLs(context.Background(), dir)
	if err != nil || !slices.Equal(got, []string{"git@github.com:fnune/doriath.git", "https://example.com/mirror.git"}) {
		t.Errorf("remotes = %v, %v", got, err)
	}
	if _, err := gitRemoteURLs(context.Background(), t.TempDir()+"/missing"); err == nil {
		t.Error("a directory that does not exist has no remotes to list")
	}
}
