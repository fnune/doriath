package termbar

import (
	"bytes"
	"testing"
)

func scan(chunks ...string) (string, *scanner) {
	s := &scanner{rows: 24}
	var out bytes.Buffer
	for _, c := range chunks {
		s.feed([]byte(c), &out)
	}
	return out.String(), s
}

func TestTheProgramsOutputPassesUnchanged(t *testing.T) {
	in := "hello \x1b[1;31mred\x1b[0m\r\n\x1b]0;title\x07\x1b]8;;https://x\x1b\\link\x1b(B\x1b[5;10r\x1b[3;4H\x1b[K\x1b[3J"
	if got, s := scan(in); got != in || s.barErased {
		t.Errorf("got %q, redraw %v", got, s.barErased)
	}
}

func TestAScrollRegionToTheBottomStopsAboveTheBar(t *testing.T) {
	for in, want := range map[string]string{
		"\x1b[r":        "\x1b[1;23r",
		"\x1b[;r":       "\x1b[1;23r",
		"\x1b[2r":       "\x1b[2;23r",
		"\x1b[1;24r":    "\x1b[1;23r",
		"\x1b[1;99r":    "\x1b[1;23r",
		"\x1b[4;12r":    "\x1b[4;12r",
		"\x1b[?1;2r":    "\x1b[?1;2r",
		"\x1b[99;1H":    "\x1b[23;1H",
		"\x1b[999;999H": "\x1b[23;999H",
		"\x1b[24f":      "\x1b[23;1f",
		"\x1b[50d":      "\x1b[23d",
		"\x1b[23;5H":    "\x1b[23;5H",
	} {
		if got, _ := scan(in); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}

func TestErasingTheScreenOrSwitchingItRedrawsTheBar(t *testing.T) {
	for _, in := range []string{"\x1b[J", "\x1b[0J", "\x1b[2J", "\x1bc", "\x1b[!p", "\x1b[?1049h", "\x1b[?25;1049l", "\x1b[?47h"} {
		if got, s := scan(in); !s.barErased || got != in {
			t.Errorf("%q: redraw %v, out %q", in, s.barErased, got)
		}
	}
	for _, in := range []string{"\x1b[1J", "\x1b[3J", "\x1b[?25h", "\x1b[?2026l"} {
		if _, s := scan(in); s.barErased {
			t.Errorf("%q redraws the bar", in)
		}
	}
}

func TestASequenceSplitAcrossReadsIsStillRewritten(t *testing.T) {
	got, s := scan("a\x1b", "[", "r", "b")
	if got != "a\x1b[1;23rb" || !s.idle() {
		t.Errorf("got %q, idle %v", got, s.idle())
	}
}

func TestTheBarWaitsForTheEndOfASequenceOrCharacter(t *testing.T) {
	for _, chunk := range []string{"\x1b[3", "\x1b]0;ti", "\xe2\x94", "\x1b]0;x\x1b"} {
		if _, s := scan(chunk); s.idle() {
			t.Errorf("%q: idle", chunk)
		}
	}
	if _, s := scan("\xe2\x94\x80"); !s.idle() {
		t.Error("a whole character is not idle")
	}
}

func TestAnEscapeInsideAStringStartsANewSequence(t *testing.T) {
	if got, _ := scan("\x1b]0;x\x1b[r"); got != "\x1b]0;x\x1b[1;23r" {
		t.Errorf("got %q", got)
	}
}
