package session

import (
	"fmt"
	"strings"
)

// Printable shows control characters and bidirectional overrides in s as
// escapes, so that text the agent wrote, such as a request's summary,
// cannot move the cursor, retitle or reprogram your terminal, or reorder
// what you read, when doriath prints it on the host.
func Printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r != '\n' && r != '\t' && unprintable(r) {
			fmt.Fprintf(&b, "\\u%04x", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// PrintableLine is Printable for text that must stay on one line, such as an
// entry of a list.
func PrintableLine(s string) string {
	return Printable(strings.NewReplacer("\n", `\n`, "\t", `\t`).Replace(s))
}

func unprintable(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x200e, r == 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}
