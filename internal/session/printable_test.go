package session

import "testing"

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
