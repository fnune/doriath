package main

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"

	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/oauth"
	"github.com/fnune/doriath/internal/profile"
)

// cmdLogin signs in once, on the host, for a profile's OAuth secrets.
// Sessions then get fresh tokens without asking.
func cmdLogin(p config.Paths, l *profile.Loader, args []string, w io.Writer) error {
	prof, err := l.Load(args[0])
	if err != nil {
		return err
	}
	var targets []string
	if len(args) == 2 {
		s := args[1]
		if b, ok := prof.Secrets[s]; !ok || b.OAuth == nil {
			return fmt.Errorf("login: profile %s has no [secrets.%s] with oauth", prof.Name, s)
		}
		targets = []string{s}
	} else {
		for _, s := range slices.Sorted(maps.Keys(prof.Secrets)) {
			if prof.Secrets[s].OAuth == nil {
				continue
			}
			if _, err := os.Stat(oauth.StatePath(p.State, prof.SecretOwner(s), s)); err == nil {
				fmt.Fprintf(w, "Already signed in for %s; name it to sign in again.\n", s)
				continue
			}
			targets = append(targets, s)
		}
		if len(targets) == 0 {
			fmt.Fprintf(w, "Nothing to sign in to in profile %s.\n", prof.Name)
			return nil
		}
	}
	for _, s := range targets {
		fmt.Fprintf(w, "Signing in for %s.\n", s)
		if err := oauth.Login(context.Background(), *prof.Secrets[s].OAuth, oauth.StatePath(p.State, prof.SecretOwner(s), s), opener{}, w); err != nil {
			return fmt.Errorf("login %s: %w", s, err)
		}
		fmt.Fprintf(w, "Signed in for %s in profile %s.\n", s, prof.SecretOwner(s))
	}
	return nil
}
