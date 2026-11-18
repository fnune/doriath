package session

import (
	"fmt"
	"strings"

	"github.com/fnune/doriath/internal/term"
)

// Printable shows control characters, bidirectional overrides and
// zero-width characters in s as escapes, so that text the agent wrote, such as a request's summary,
// cannot move the cursor, retitle or reprogram your terminal, or reorder
// what you read, when doriath prints it on the host.
func Printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r != '\n' && r != '\t' && term.Unprintable(r) {
			fmt.Fprintf(&b, "\\u%04x", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func PrintableLine(s string) string {
	return Printable(strings.NewReplacer("\n", `\n`, "\t", `\t`).Replace(s))
}
