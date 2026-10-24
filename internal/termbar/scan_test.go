package termbar

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
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
	for _, in := range []string{"\x1b[J", "\x1b[0J", "\x1b[2J", "\x1b[?1049h", "\x1b[?25;1049l", "\x1b[?47h"} {
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

func TestTheTerminalNeverSeesAClipboardRead(t *testing.T) {
	for _, in := range []string{
		"\x1b]52;c;?\x07",
		"\x1b]52;c;?\x1b\\",
		"\x1b]52;;?\x07",
		"\x1b]52;pqs01;?\x07",
		"\x1b]052;c;?\x07",
		"\x1b]52;?\x07",
		"\x1b]52;c;?junk\x07",
		"\x1b]52;c;?\x9c",
		"\x1b]52;" + strings.Repeat("c", 300) + ";?\x07",
		"\x1b]" + strings.Repeat("0", 300) + "52;c;?\x07",
	} {
		got, s := scan(in, "x")
		if got != "x" || !s.idle() {
			t.Errorf("%.16q: got %.16q, idle %v", in, got, s.idle())
		}
	}
	if got, _ := scan("\x1b]5", "2;c", ";", "?", "\x1b", "\\x"); got != "x" {
		t.Errorf("split read: got %q", got)
	}
	if got, _ := scan("\x1b]52;c;?\x1b", "[r"); got != "\x1b[1;23r" {
		t.Errorf("cancelled read: got %q", got)
	}
}

func TestClipboardWritesAndOtherStringsPass(t *testing.T) {
	for _, in := range []string{
		"\x1b]52;c;aGVsbG8=\x07",
		"\x1b]52;c;aGVsbG8=\x1b\\",
		"\x1b]52;c;\x07",
		"\x1b]52;c\x07",
		"\x1b]5;0;?\x07",
		"\x1b]4;1;?\x07",
		"\x1b]520;c;?\x07",
		"\x1b]8;;https://x/?a=1\x1b\\",
		"\x1b]133;A\x07",
		"\x1b]104\x07",
	} {
		if got, s := scan(in); got != in || !s.idle() {
			t.Errorf("%q: got %q, idle %v", in, got, s.idle())
		}
	}
}

func TestTheBarFillsTheWholeRow(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	for cols, want := range map[int]string{
		20: "doriath work      ",
		8:  "doria…",
	} {
		b := &Bar{cols: cols, text: "doriath work"}
		if got := b.render(); got != want && got != " "+want+" " {
			t.Errorf("cols %d: %q, want %q", cols, got, want)
		}
	}
}

func TestAnOverlongSequenceCannotReachTheBar(t *testing.T) {
	zeros := strings.Repeat("0", 300)
	for _, in := range []string{
		"\x1b[" + zeros + "24;1H",
		"\x1b[" + zeros + "1;24r",
		"\x1b[1;" + zeros + "24r",
	} {
		got, s := scan(in, "x")
		if got != "x" || !s.idle() {
			t.Errorf("%.12q: got %q, idle %v", in, got, s.idle())
		}
	}
}

func TestEscapeIntermediatesStopGrowing(t *testing.T) {
	got, s := scan("\x1b", strings.Repeat(" ", 1<<20), "Fx")
	if got != "x" || cap(s.seq) > 2*maxSequence || !s.idle() {
		t.Errorf("got %q, kept %d bytes, idle %v", got, cap(s.seq), s.idle())
	}
}

func TestAResetKeepsTheBarRowAtOnce(t *testing.T) {
	region := saveCursor + "\x1b[1;23r" + restoreCursor
	for in, want := range map[string]string{
		"\x1b[!p\n\nFAKE\xf0": "\x1b[!p" + region + "\n\nFAKE\xf0",
		"\x1bc\n\nFAKE\xf0":   "\x1bc" + region + "\n\nFAKE\xf0",
	} {
		if got, s := scan(in); got != want || !s.barErased {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}

func TestARowWithSubparametersOrManyDigitsStopsAboveTheBar(t *testing.T) {
	for in, want := range map[string]string{
		"\x1b[24:0H":                 "\x1b[23;1H",
		"\x1b[1:24H":                 "\x1b[23;1H",
		"\x1b[24:0d":                 "\x1b[23d",
		"\x1b[1;24:0r":               "\x1b[1;23r",
		"\x1b[99999999999999999999H": "\x1b[23;1H",
		"\x1b[00000000000000000024H": "\x1b[23;1H",
		"\x1b[5:0;3H":                "\x1b[5:0;3H",
	} {
		if got, _ := scan(in); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}

func TestStrayEightBitControlsAreDropped(t *testing.T) {
	for in, want := range map[string]string{
		"a\x9b24;1Hb":          "a24;1Hb",
		"\x9d0;x\x07":          "0;x\x07",
		"\xc3\x9b\xe2\x94\x80": "\xc3\x9b\xe2\x94\x80",
	} {
		if got, _ := scan(in); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}

func TestClosingTurnsOffWhatTheProgramLeftOn(t *testing.T) {
	master, tty, err := openPty()
	if err != nil {
		t.Skip(err)
	}
	defer master.Close()
	defer tty.Close()
	saved, err := unix.IoctlGetTermios(int(tty.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	other, otherTTY, err := openPty()
	if err != nil {
		t.Fatal(err)
	}
	defer otherTTY.Close()
	b := &Bar{in: tty, out: tty, master: other, saved: saved, winch: make(chan os.Signal), drained: make(chan struct{}), scan: scanner{rows: 24}}
	close(b.drained)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 4096)
	n, _ := master.Read(p)
	if got := string(p[:n]); !strings.HasPrefix(got, restoreModes) {
		t.Errorf("got %q", got)
	}
	for _, mode := range []string{"?1049l", "?25h", "?1000l", "?1002l", "?1003l", "?1006l", "?2004l", "<u"} {
		if !strings.Contains(restoreModes, "\x1b["+mode) {
			t.Errorf("%s is left on", mode)
		}
	}
}

func TestAnEscapeInsideASequenceStartsANewOne(t *testing.T) {
	for in, want := range map[string]string{
		"\x1b[0\x1b[24;1H": "\x1b[0\x1b[23;1H",
		"\x1b[" + strings.Repeat("0", 300) + "\x1b[24;1H": "\x1b[23;1H",
		"\x1b" + strings.Repeat(" ", 300) + "\x1b[24;1H":  "\x1b[23;1H",
	} {
		if got, _ := scan(in); got != want {
			t.Errorf("%.12q = %q, want %q", in, got, want)
		}
	}
}
