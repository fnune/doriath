package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/fnune/girdle/internal/oauth"
)

// cmdLogin signs in once, on the host, for a profile's OAuth secret.
// Sessions then get fresh tokens without asking.
func cmdLogin(args []string, w io.Writer) error {
	if len(args) != 2 {
		return errors.New("login: usage: girdle login PROFILE SECRET")
	}
	p, err := paths()
	if err != nil {
		return err
	}
	prof, err := loader(p).Load(args[0])
	if err != nil {
		return err
	}
	b, ok := prof.Secrets[args[1]]
	if !ok || b.OAuth == nil {
		return fmt.Errorf("login: profile %s has no [secrets.%s] with oauth", args[0], args[1])
	}
	path := oauth.StatePath(p.State, prof.Name, args[1])
	if err := oauth.Login(context.Background(), *b.OAuth, path, opener{}, w); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	fmt.Fprintf(w, "Signed in for %s in profile %s.\n", args[1], prof.Name)
	return nil
}
