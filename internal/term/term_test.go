package term

import (
	"bytes"
	"testing"
)

func TestTitleSavesSetsAndRestores(t *testing.T) {
	var out bytes.Buffer
	restore := Title(&out, "doriath · work\x1b]0;evil\x07")
	if got := out.String(); got != "\x1b[22;0t\x1b]0;doriath · work]0;evil\x07" {
		t.Errorf("set = %q", got)
	}
	out.Reset()
	restore()
	if out.String() != "\x1b[23;0t" {
		t.Errorf("restore = %q", out.String())
	}
}

func TestLinesOutsideATerminalHaveNoColors(t *testing.T) {
	var out bytes.Buffer
	w := New(&out)
	w.Header("work", "session s1")
	w.Line(Warn, "first\n[egress]")
	want := "doriath · work · session s1\n  ! first\n      [egress]\n"
	if out.String() != want {
		t.Errorf("got %q, want %q", out.String(), want)
	}
}

func TestABadgeTakesTheTerminalsBackgroundAsItsTextColor(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	if got := Badge("doriath work"); got != "\x1b[35;7m doriath work \x1b[0m" {
		t.Errorf("badge = %q", got)
	}
	t.Setenv("NO_COLOR", "1")
	if got := Badge("doriath work"); got != "doriath work" {
		t.Errorf("with NO_COLOR = %q", got)
	}
}
