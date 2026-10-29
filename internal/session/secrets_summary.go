package session

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// Summary is the session in one line, for the bar. The
// secrets take at most secretsWidth characters.
func (st Status) Summary(secretsWidth int) string {
	session := "session " + st.Session
	if st.Description != "" {
		session += " “" + st.Description + "”"
	}
	parts := []string{"doriath " + st.Profile, session, fmt.Sprintf("%d hosts", len(st.Hosts)+len(st.Intercepted))}
	if st.Pending > 0 {
		parts = append(parts, fmt.Sprintf("%d waiting for you", st.Pending))
	}
	if n := len(st.Denied); n > 0 {
		parts = append(parts, fmt.Sprintf("%d blocked", n))
	}
	if secrets := st.SecretsSummary(secretsWidth); secrets != "" {
		parts = append(parts, secrets)
	}
	return strings.Join(parts, " · ")
}

// SecretsSummary names the session's secrets in at most width characters.
// It names each secret when they fit, then only the missing ones, then
// only counts. A width of 0 or less takes the shortest form.
func (st Status) SecretsSummary(width int) string {
	if len(st.Secrets) == 0 {
		return ""
	}
	var read, missing []string
	for _, name := range st.Secrets {
		if slices.ContainsFunc(st.Unavailable, func(m Missing) bool { return m.Secret == name }) {
			missing = append(missing, name)
		} else {
			read = append(read, name)
		}
	}
	counts := fmt.Sprintf("%d secrets", len(st.Secrets))
	if len(missing) > 0 {
		counts = fmt.Sprintf("%d/%d secrets", len(read), len(st.Secrets))
	}
	forms := []string{counts}
	if len(missing) > 0 {
		forms = append([]string{counts + ", missing " + strings.Join(missing, ", ")}, forms...)
	}
	named := "secrets " + strings.Join(read, ", ")
	switch {
	case len(read) == 0:
		named = "secrets missing " + strings.Join(missing, ", ")
	case len(missing) > 0:
		named += ", missing " + strings.Join(missing, ", ")
	}
	forms = append([]string{named}, forms...)
	for _, f := range forms {
		if utf8.RuneCountInString(f) <= width {
			return f
		}
	}
	return forms[len(forms)-1]
}
