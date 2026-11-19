package session

import (
	"strings"
	"testing"
)

func TestPrintableEscapesTerminalControls(t *testing.T) {
	for in, want := range map[string]string{
		"Push to\x1b]0;owned\x07 a repo": `Push to\u001b]0;owned\u0007 a repo`,
		"csi \u009b2J":                   `csi \u009b2J`,
		"rm -rf \u202e/ emoh":            "rm -rf \\u202e/ emoh",
		"line\n\tnext ünïcode":           "line\n\tnext ünïcode",
		"cr\roverwrite":                  `cr\u000doverwrite`,
		"rm\u200b -rf\u2060 \ufeff/":     `rm\u200b -rf\u2060 \ufeff/`,
		"one\u2028two\u2029three":        `one\u2028two\u2029three`,
	} {
		if got := Printable(in); got != want {
			t.Errorf("Printable(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPrintableLineKeepsAnEntryOnOneLine(t *testing.T) {
	if got := PrintableLine("a\n\tb\x1b"); got != `a\n\tb\u001b` {
		t.Errorf("PrintableLine = %q", got)
	}
}

func TestTheStatusTextShowsAHostThatCarriesControlsAsEscapes(t *testing.T) {
	st := Status{Session: "s1", Profile: "p", Denied: []Denial{{Target: "a\u009b31m.example\u3164.com:443", Reason: "host not in the profile\u202e", Count: 1}}}
	got := st.Describe()
	for _, raw := range []string{"\u009b", "\u3164", "\u202e"} {
		if strings.Contains(got, raw) {
			t.Errorf("the status text holds %q", raw)
		}
	}
	if !strings.Contains(got, `a\u009b31m.example\u3164.com:443`) {
		t.Errorf("status text:\n%s", got)
	}
}
