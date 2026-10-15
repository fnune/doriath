package session

import (
	"fmt"
	"strings"

	"github.com/fnune/girdle/internal/approval"
)

const summaryHosts = 3

// Summary is one line for the end of a session. It is empty when nothing was
// blocked or decided, so a quiet session ends quietly.
func Summary(profile, id string, denied []Denial, history []approval.Outcome) string {
	var parts []string
	if len(denied) > 0 {
		hosts := make([]string, 0, summaryHosts)
		for i, d := range denied {
			if i == summaryHosts {
				hosts = append(hosts, fmt.Sprintf("%d more", len(denied)-summaryHosts))
				break
			}
			hosts = append(hosts, fmt.Sprintf("%s (%d)", d.Host, d.Count))
		}
		parts = append(parts, "blocked "+strings.Join(hosts, ", "))
	}
	counts := map[approval.Verdict]int{}
	for _, o := range history {
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
		parts = append(parts, "requests "+strings.Join(decided, ", "))
	}
	if len(parts) == 0 {
		return ""
	}
	return Printable(fmt.Sprintf("girdle: session %s (%s) ended: %s. Details: girdle log --session %s", id, profile, strings.Join(parts, "; "), id))
}
