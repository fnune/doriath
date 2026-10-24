package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/fnune/doriath/internal/allowed"
	"github.com/fnune/doriath/internal/profile"
)

type grantStore interface {
	Grants(key allowed.Key) ([]string, bool, error)
	Allow(key allowed.Key, grants []string) error
}

func allowedKey(prof *profile.Profile, dir string) allowed.Key {
	return allowed.Key{Profile: prof.Name, Repository: profile.FindRepository(dir, func(p string) bool { return osKind(p) != "" })}
}

func confirmProfile(store grantStore, prof *profile.Profile, key allowed.Key, in io.Reader, out io.Writer, terminal bool) error {
	grants, err := prof.Grants()
	if err != nil {
		return err
	}
	approved, seen, err := store.Grants(key)
	if err != nil {
		return err
	}
	added := profile.Added(approved, grants)
	if seen && len(added) == 0 {
		if slices.Equal(approved, grants) {
			return nil
		}
		return store.Allow(key, grants)
	}
	if err := describeGrants(out, prof, key, seen, added); err != nil {
		return err
	}
	if !terminal {
		return fmt.Errorf("profile %s waits for your answer, and this session has no terminal to ask in. To allow it, run on the host: %s", prof.Name, allowCommand(key))
	}
	fmt.Fprint(out, "\nAllow? [y/N] ")
	answer, _ := bufio.NewReader(in).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return store.Allow(key, grants)
	}
	return errors.New("you did not allow profile " + prof.Name)
}

func describeGrants(out io.Writer, prof *profile.Profile, key allowed.Key, seen bool, added []string) error {
	where := ""
	if key.Repository != "" {
		where = " in " + key.Repository
	}
	if !seen {
		fmt.Fprintf(out, "You have not allowed profile %s%s yet. It gives the jail:\n\n", prof.Name, where)
		if err := summarizeProfile(out, prof); err != nil {
			return err
		}
		fmt.Fprintf(out, "\ndoriath profiles show %s lists where each entry comes from.\n", prof.Name)
		return nil
	}
	fmt.Fprintf(out, "Profile %s%s gives the jail more than when you allowed it:\n\n", prof.Name, where)
	for _, line := range readableAdditions(added) {
		fmt.Fprintln(out, "  + "+line)
	}
	return nil
}

func readableAdditions(added []string) []string {
	var out []string
	for _, line := range added {
		list, _, isOrder := strings.Cut(line, profile.OrderSuffix)
		if !isOrder {
			out = append(out, line)
			continue
		}
		if !slices.ContainsFunc(added, func(other string) bool {
			return strings.HasPrefix(other, list+": ") || strings.HasPrefix(other, list+"[")
		}) {
			out = append(out, list+": in a new order")
		}
	}
	return out
}

func allowCommand(key allowed.Key) string {
	if key.Repository == "" {
		return "doriath profiles allow " + key.Profile
	}
	return fmt.Sprintf("doriath profiles allow %s --current %s", key.Profile, key.Repository)
}

func profilesAllow(l *profile.Loader, store grantStore, name, dir string, out io.Writer) error {
	prof, err := l.Load(name)
	if err != nil {
		return err
	}
	grants, err := prof.Grants()
	if err != nil {
		return err
	}
	key := allowedKey(prof, dir)
	approved, seen, err := store.Grants(key)
	if err != nil {
		return err
	}
	if added := profile.Added(approved, grants); !seen || len(added) > 0 {
		if err := describeGrants(out, prof, key, seen, added); err != nil {
			return err
		}
	}
	if err := store.Allow(key, grants); err != nil {
		return err
	}
	fmt.Fprintf(out, "\nAllowed profile %s.\n", prof.Name)
	return nil
}
