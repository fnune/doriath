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
	if got := Badge("doriath work"); got != "\x1b[34;7m doriath work \x1b[0m" {
		t.Errorf("badge = %q", got)
	}
	t.Setenv("NO_COLOR", "1")
	if got := Badge("doriath work"); got != "doriath work" {
		t.Errorf("with NO_COLOR = %q", got)
	}
}

func TestABarDrawsInPlaceAndClears(t *testing.T) {
	var out bytes.Buffer
	b := (&Writer{w: &out, tty: true}).Bar()
	b.Show(0.5, "pack 1 of 2")
	b.Show(1.5, "pack 2 of 2")
	b.Clear()
	b.Clear()
	want := "\r\x1b[2K  ━━━━━━━━━━━━━━━━━━━━  50% pack 1 of 2" +
		"\r\x1b[2K  ━━━━━━━━━━━━━━━━━━━━ 100% pack 2 of 2" +
		"\r\x1b[2K"
	if out.String() != want {
		t.Errorf("got %q, want %q", out.String(), want)
	}
}

func TestABarOutsideATerminalDrawsNothing(t *testing.T) {
	var out bytes.Buffer
	b := New(&out).Bar()
	b.Show(0.5, "pack 1 of 2")
	b.Clear()
	if out.Len() != 0 {
		t.Errorf("got %q", out.String())
	}
}

func TestInvisibleAndBidiCharactersAreUnprintable(t *testing.T) {
	for _, r := range []rune{0x00ad, 0x034f, 0x061c, 0x115f, 0x1160, 0x17b4, 0x180e, 0x200b, 0x202e, 0x2061, 0x2064, 0x2066, 0x3164, 0xfe0f, 0xfeff, 0xffa0, 0xfffc, 0xe0041, 0xe0100, 0x85, 0x9b} {
		if !Unprintable(r) {
			t.Errorf("U+%04X passes as printable", r)
		}
	}
	for _, r := range []rune{'a', ' ', 'é', 'ж', '日', '→', '“'} {
		if Unprintable(r) {
			t.Errorf("%q is unprintable", r)
		}
	}
}
