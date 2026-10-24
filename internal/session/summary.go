package session

import (
	"fmt"
	"io"
	"strings"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/proxy"
	"github.com/fnune/doriath/internal/term"
)

type note struct {
	level term.Level
	text  string
}

func summary(denied []Denial, history []approval.Outcome) []note {
	var out []note
	for _, d := range denied {
		times := "1 time"
		if d.Count != 1 {
			times = fmt.Sprintf("%d times", d.Count)
		}
		if d.Reason == proxy.ReasonRefused {
			out = append(out, note{term.Refused, Printable(fmt.Sprintf("%s refused %s, as the profile says", d.Target, times))})
			continue
		}
		out = append(out, note{term.Problem, Printable(fmt.Sprintf("%s blocked %s: %s", d.Target, times, d.Reason))})
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
		out = append(out, note{term.Info, "requests: " + strings.Join(decided, ", ")})
	}
	return out
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
		t.Line(n.level, n.text)
	}
}
