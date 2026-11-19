package main

import (
	"bytes"
	"testing"
)

func TestPrintableLinesEscapesControlsInEachLine(t *testing.T) {
	var out bytes.Buffer
	w := printableLines(&out)
	_, _ = w.Write([]byte("branch \u202eevil\x1b]0;x"))
	_, _ = w.Write([]byte("\u0007 is back\nsecond\n"))
	want := "branch \\u202eevil\\u001b]0;x\\u0007 is back\nsecond\n"
	if out.String() != want {
		t.Errorf("got %q, want %q", out.String(), want)
	}
}
