package session

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/proxy"
	"github.com/fnune/doriath/internal/term"
)

type note struct {
	level term.Level
	text  string
}

type ending struct {
	fixed, needs, network []note
}

const hostsShown = 5

func summary(denied []Denial, history []approval.Outcome) (fixed, network []note) {
	type group struct {
		level term.Level
		label string
		total int
		hosts []string
	}
	var groups []*group
	byLabel := map[string]*group{}
	for _, d := range denied {
		if d.Path {
			fixed = append(fixed, note{term.Action, Printable(d.Target + ": " + d.Reason)})
			continue
		}
		level, label := term.Blocked, "blocked: "+d.Reason
		if d.Reason == proxy.ReasonRefused {
			level, label = term.Refused, d.Reason
		}
		g := byLabel[label]
		if g == nil {
			g = &group{level: level, label: label}
			byLabel[label] = g
			groups = append(groups, g)
		}
		g.total += d.Count
		g.hosts = append(g.hosts, fmt.Sprintf("%s ×%d", d.Target, d.Count))
	}
	slices.SortStableFunc(groups, func(a, b *group) int { return cmp.Compare(b.level, a.level) })
	width := 0
	for _, g := range groups {
		g.label = fmt.Sprintf("%d %s", g.total, g.label)
		width = max(width, utf8.RuneCountInString(g.label))
	}
	for _, g := range groups {
		hosts := g.hosts
		if len(hosts) > hostsShown {
			hosts = append(hosts[:hostsShown:hostsShown], fmt.Sprintf("and %d more", len(g.hosts)-hostsShown))
		}
		pad := strings.Repeat(" ", width-utf8.RuneCountInString(g.label)+3)
		network = append(network, note{g.level, Printable(g.label + pad + strings.Join(hosts, ", "))})
	}
	counts := map[approval.Verdict]int{}
	for _, o := range history {
		if o.Request.Kind == approval.KindSecret {
			continue
		}
		counts[o.Decision.Verdict]++
	}
	var decided []string
	for _, v := range []approval.Verdict{approval.VerdictAllow, approval.VerdictDeny, approval.VerdictNone} {
		if n := counts[v]; n > 0 {
			label := map[approval.Verdict]string{approval.VerdictAllow: "allowed", approval.VerdictDeny: "denied", approval.VerdictNone: "expired"}[v]
			decided = append(decided, fmt.Sprintf("%d %s", n, label))
		}
	}
	if len(decided) > 0 {
		network = append(network, note{term.OK, strings.Join(decided, ", ")})
	}
	return fixed, network
}

func notesOf(level term.Level, text string) []note {
	var out []note
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if line != "" {
			out = append(out, note{level, Printable(line)})
		}
	}
	return out
}

func (e ending) print(t *term.Writer, details string, header ...string) {
	if len(e.fixed)+len(e.needs)+len(e.network) == 0 {
		return
	}
	t.Header(header...)
	for _, s := range []struct {
		title string
		notes []note
	}{{"Fixed for you", e.fixed}, {"Needs you", e.needs}, {"Network", e.network}} {
		if len(s.notes) == 0 {
			continue
		}
		in := t.Section(s.title)
		for _, n := range s.notes {
			in.Line(n.level, Printable(n.text))
		}
	}
	t.Line(term.Next, t.Dim(details))
}

const noteIndent = len("  · ")

func noteWidth(w io.Writer) int {
	if width := term.Width(w); width > noteIndent {
		return width - noteIndent
	}
	return 80
}

func printBlock(t *term.Writer, notes []note, header ...string) {
	if len(notes) == 0 {
		return
	}
	t.Header(header...)
	for _, n := range notes {
		t.Line(n.level, Printable(n.text))
	}
}
