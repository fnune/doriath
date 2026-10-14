package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"

	"github.com/fnune/girdle/internal/oauth"
)

// cmdLogin signs in once, on the host, for a profile's OAuth secrets.
// Sessions then get fresh tokens without asking.
func cmdLogin(args []string, w io.Writer) error {
	flags := flag.NewFlagSet("login", flag.ContinueOnError)
	name := flags.String("profile", "", "the profile whose OAuth secrets to sign in to (required)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *name == "" || flags.NArg() > 1 {
		return errors.New("login: usage: girdle login --profile NAME [SECRET]")
	}
	p, err := paths()
	if err != nil {
		return err
	}
	prof, err := loader(p).Load(*name)
	if err != nil {
		return err
	}
	var targets []string
	if s := flags.Arg(0); s != "" {
		if b, ok := prof.Secrets[s]; !ok || b.OAuth == nil {
			return fmt.Errorf("login: profile %s has no [secrets.%s] with oauth", prof.Name, s)
		}
		targets = []string{s}
	} else {
		for _, s := range slices.Sorted(maps.Keys(prof.Secrets)) {
			if prof.Secrets[s].OAuth == nil {
				continue
			}
			if _, err := os.Stat(oauth.StatePath(p.State, prof.Name, s)); err == nil {
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
		if err := oauth.Login(context.Background(), *prof.Secrets[s].OAuth, oauth.StatePath(p.State, prof.Name, s), opener{}, w); err != nil {
			return fmt.Errorf("login %s: %w", s, err)
		}
		fmt.Fprintf(w, "Signed in for %s in profile %s.\n", s, prof.Name)
	}
	return nil
}
