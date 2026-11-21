package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/fnune/doriath/internal/config"
	"github.com/fnune/doriath/internal/oauth"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/secret"
)

func cmdLogin(p config.Paths, l *profile.Loader, args []string, in io.Reader, kr, logins secret.Keyring, w io.Writer) error {
	if err := oauth.Migrate(p.State, logins); err != nil {
		return fmt.Errorf("login: move the OAuth logins into the keyring: %w", err)
	}
	prof, err := l.Load(args[0])
	if err != nil {
		return err
	}
	var targets []string
	if len(args) == 2 {
		s := args[1]
		if b, ok := prof.Secrets[s]; !ok || (b.OAuth == nil && !b.Keyring) {
			return fmt.Errorf("login: profile %s has no [secrets.%s] with oauth or keyring", prof.Name, s)
		}
		targets = []string{s}
	} else {
		for _, s := range slices.Sorted(maps.Keys(prof.Secrets)) {
			done, err := loggedIn(prof, kr, logins, s)
			if err != nil {
				return fmt.Errorf("login %s: %w", s, err)
			}
			switch {
			case done && prof.Secrets[s].Keyring:
				fmt.Fprintf(w, "Secret %s is already in the keyring; name it to replace it.\n", s)
				continue
			case done:
				fmt.Fprintf(w, "Already signed in for %s; name it to sign in again.\n", s)
				continue
			}
			if b := prof.Secrets[s]; b.OAuth != nil || b.Keyring {
				targets = append(targets, s)
			}
		}
		if len(targets) == 0 {
			fmt.Fprintf(w, "Nothing to sign in to in profile %s.\n", prof.Name)
			return nil
		}
	}
	for _, s := range targets {
		owner := prof.SecretOwner(s)
		if prof.Secrets[s].Keyring {
			if err := storeInKeyring(in, kr, owner, s, w); err != nil {
				return fmt.Errorf("login %s: %w", s, err)
			}
			fmt.Fprintf(w, "Stored %s in the keyring for profile %s.\n", s, owner)
			continue
		}
		fmt.Fprintf(w, "Signing in for %s.\n", s)
		if err := oauth.Login(context.Background(), *prof.Secrets[s].OAuth, logins, owner, s, opener{}, w); err != nil {
			return fmt.Errorf("login %s: %w", s, err)
		}
		if module, shared := strings.CutPrefix(owner, profile.SharedOwnerPrefix); shared {
			fmt.Fprintf(w, "Signed in for %s. Every profile with the module %s shares this login.\n", s, module)
			continue
		}
		fmt.Fprintf(w, "Signed in for %s in profile %s.\n", s, owner)
	}
	return nil
}

func loggedIn(prof *profile.Profile, kr, logins secret.Keyring, s string) (bool, error) {
	b := prof.Secrets[s]
	switch {
	case b.OAuth != nil:
		return oauth.SignedIn(logins, prof.SecretOwner(s), s), nil
	case b.Keyring:
		_, err := kr.Read(prof.SecretOwner(s), s)
		if errors.Is(err, secret.ErrNotInKeyring) {
			return false, nil
		}
		return err == nil, err
	}
	return false, nil
}

func storeInKeyring(in io.Reader, kr secret.Keyring, owner, s string, w io.Writer) error {
	value, err := readSecretValue(in, w, s)
	if err != nil {
		return err
	}
	if len(value) == 0 {
		return fmt.Errorf("secret %q is empty", s)
	}
	return kr.Write(owner, s, secret.NewValue(value))
}
