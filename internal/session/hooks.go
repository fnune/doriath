package session

import (
	"context"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/fnune/doriath/internal/jail"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/vcs"
)

const hooksFolderReason = "git runs the hooks in this folder on your machine, such as at your next commit, because core.hooksPath names it."

type hooksPathReader func(configFile string) string

func gitHooksPath(git string) hooksPathReader {
	return func(configFile string) string {
		if git == "" {
			return ""
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		scope := []string{"--global"}
		if configFile != "" {
			scope = []string{"--file", configFile}
		}
		args := append([]string{"config"}, scope...)
		out, err := exec.CommandContext(ctx, git, append(args, "--includes", "--type=path", "--get", "core.hooksPath")...).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
}

func withHookFolders(p *profile.Profile, host jail.Host, read hooksPathReader) *profile.Profile {
	global := read("")
	var folders []string
	for _, m := range p.Mounts {
		if m.Mode != profile.ModeWrite {
			continue
		}
		for _, repo := range jail.Repositories(m.Path, host) {
			root := vcs.Root(repo)
			store := vcs.Store(root)
			if store == "" {
				continue
			}
			configured := read(filepath.Join(store, "config"))
			if configured == "" {
				configured = global
			}
			if configured == "" {
				continue
			}
			roots := []string{root}
			if !filepath.IsAbs(configured) {
				roots = append(roots, vcs.WorktreeCheckouts(store)...)
			}
			for _, base := range roots {
				folder := filepath.Clean(configured)
				if !filepath.IsAbs(configured) {
					folder = filepath.Join(base, configured)
				}
				if within(folder, m.Path) && !within(folder, store) && !slices.Contains(folders, folder) {
					folders = append(folders, folder)
				}
			}
		}
	}
	if len(folders) == 0 {
		return p
	}
	out := *p
	out.Mounts = slices.Clone(p.Mounts)
	out.PathRules.Hold = slices.Clone(p.PathRules.Hold)
	for _, folder := range folders {
		out.Mounts = append(out.Mounts, profile.Mount{Path: folder, Mode: profile.ModeRead, Missing: profile.MissingHold})
		out.PathRules.Hold = append(out.PathRules.Hold, profile.PathHold{Path: folder, Reason: hooksFolderReason, Missing: profile.MissingHold, Folder: true})
	}
	return &out
}
