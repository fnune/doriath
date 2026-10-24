package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/fnune/doriath/internal/allowed"
	"github.com/fnune/doriath/internal/cli"
	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/session"
	"github.com/fnune/doriath/internal/term"
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
	removed := profile.Removed(approved, grants)
	if seen && len(added) == 0 && len(removed) == 0 {
		if slices.Equal(approved, grants) {
			return nil
		}
		return store.Allow(key, grants)
	}
	describeGrants(out, prof, key, seen, added, removed)
	if !terminal {
		return fmt.Errorf("profile %s waits for your answer, and this session has no terminal to ask in. To allow it, run on the host: %s", prof.Name, cli.Code(allowCommand(key)))
	}
	fmt.Fprint(out, "\nAllow? [y/N] ")
	answer, _ := bufio.NewReader(in).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return store.Allow(key, grants)
	}
	return errors.New("you did not allow profile " + prof.Name)
}

func describeGrants(out io.Writer, prof *profile.Profile, key allowed.Key, seen bool, added, removed []string) {
	t := term.New(out)
	where := ""
	if key.Repository != "" {
		where = " in " + key.Repository
	}
	if !seen {
		fmt.Fprintf(out, "You have not allowed profile %s%s yet. It gives the jail:\n", t.Bold(prof.Name), where)
		summarizeProfile(t, out, prof, term.Width(out))
		fmt.Fprintf(out, "\n%s\n", t.Dim(cli.Code(cli.Line("profiles", "show", prof.Name))+" lists where each entry comes from."))
		return
	}
	fmt.Fprintf(out, "Profile %s%s gives the jail more than when you allowed it:\n\n", t.Bold(prof.Name), where)
	for _, line := range readableAdditions(added) {
		name, isPass := strings.CutPrefix(line, "Env.Pass: ")
		if reason := profile.PassRisk(name); isPass && reason != "" {
			fmt.Fprintln(out, "  "+t.Tint(term.Problem, "+ "+session.PrintableLine(line)+" ("+reason+")"))
			continue
		}
		fmt.Fprintln(out, "  "+t.Tint(term.Warn, "+")+" "+session.PrintableLine(line))
	}
	if len(removed) > 0 {
		fmt.Fprintf(out, "\nIt lost lines that held the agent back:\n\n")
	}
	for _, line := range removed {
		fmt.Fprintln(out, "  "+t.Tint(term.Problem, "-")+" "+session.PrintableLine(line))
	}
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
	added, removed := profile.Added(approved, grants), profile.Removed(approved, grants)
	if !seen || len(added) > 0 || len(removed) > 0 {
		describeGrants(out, prof, key, seen, added, removed)
	}
	if err := store.Allow(key, grants); err != nil {
		return err
	}
	fmt.Fprintf(out, "\nAllowed profile %s.\n", prof.Name)
	return nil
}
