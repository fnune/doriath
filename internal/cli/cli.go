package cli

import (
	"strconv"
	"strings"
)

const Name = "doriath"

func Line(args ...string) string {
	return Words(append([]string{Name}, args...)...)
}

func Code(command string) string {
	return "`" + command + "`"
}

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

// TOMLKey is a key as TOML needs it: bare when it can be, else quoted.
func TOMLKey(key string) string {
	if key != "" && strings.IndexFunc(key, notBareKey) < 0 {
		return key
	}
	return strconv.Quote(key)
}

func notBareKey(r rune) bool {
	switch {
	case 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z', '0' <= r && r <= '9', r == '-', r == '_':
		return false
	}
	return true
}
