// Package cli spells doriath command lines for messages that tell a person
// what to run.
package cli

import "strings"

const Name = "doriath"

// Line is the doriath command line for args, quoted so that a shell runs
// it as given.
func Line(args ...string) string {
	return Words(append([]string{Name}, args...)...)
}

// Words is the command line for argv, quoted so that a shell runs it as
// given.
func Words(argv ...string) string {
	words := make([]string, len(argv))
	for i, a := range argv {
		words[i] = quote(a)
	}
	return strings.Join(words, " ")
}

func quote(s string) string {
	if s != "" && strings.IndexFunc(s, unsafe) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func unsafe(r rune) bool {
	switch {
	case 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z', '0' <= r && r <= '9':
		return false
	}
	return !strings.ContainsRune("@%+=:,./_-", r)
}
