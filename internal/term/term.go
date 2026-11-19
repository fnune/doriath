package term

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type Level int

const (
	Info Level = iota
	OK
	Warn
	Problem
	Action
	Refused
	Blocked
	Next
)

const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	dim    = "\x1b[2m"
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	cyan   = "\x1b[36m"
	badge  = "\x1b[34;7m"
)

var marks = map[Level]struct{ mark, color string }{
	Info:    {"·", dim},
	OK:      {"✓", green},
	Warn:    {"!", yellow},
	Problem: {"✕", red},
	Action:  {"↺", cyan},
	Refused: {"−", dim},
	Blocked: {"⛨", yellow},
	Next:    {"→", dim},
}

type Writer struct {
	w      io.Writer
	color  bool
	tty    bool
	indent string
}

func New(w io.Writer) *Writer {
	tty := IsTerminal(w)
	return &Writer{w: w, color: tty && os.Getenv("NO_COLOR") == "", tty: tty}
}

func Colored(w io.Writer) *Writer {
	return &Writer{w: w, color: true}
}

func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok || os.Getenv("TERM") == "dumb" {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// Width is the terminal's width in columns, or 0 when w is not a terminal.
func Width(w io.Writer) int {
	f, ok := w.(*os.File)
	if !ok || !IsTerminal(w) {
		return 0
	}
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0
	}
	return int(ws.Col)
}

func Unprintable(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x00ad, r == 0x034f, r == 0x061c, r == 0x115f, r == 0x1160, r == 0x3164, r == 0xffa0:
		return true
	case r >= 0x17b4 && r <= 0x17b5, r >= 0x180b && r <= 0x180f:
		return true
	case r >= 0x200b && r <= 0x200f, r >= 0x2028 && r <= 0x202e, r >= 0x2060 && r <= 0x206f:
		return true
	case r >= 0xfe00 && r <= 0xfe0f, r == 0xfeff, r >= 0xfff9 && r <= 0xfffc:
		return true
	case r >= 0x1d173 && r <= 0x1d17a, r >= 0xe0000 && r <= 0xe0fff:
		return true
	}
	return false
}

func Printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r != '\n' && r != '\t' && Unprintable(r) {
			fmt.Fprintf(&b, "\\u%04x", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func PrintableLine(s string) string {
	return Printable(strings.NewReplacer("\n", `\n`, "\t", `\t`).Replace(s))
}

func Title(w io.Writer, title string) (restore func()) {
	title = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, title)
	_, _ = io.WriteString(w, "\x1b[22;0t\x1b]0;"+title+"\x07")
	return func() { _, _ = io.WriteString(w, "\x1b[23;0t") }
}

func (t *Writer) paint(color, s string) string {
	if !t.color || s == "" {
		return s
	}
	return color + s + reset
}

func (t *Writer) Dim(s string) string { return t.paint(dim, s) }

func (t *Writer) Bold(s string) string { return t.paint(bold, s) }

func (t *Writer) Tint(level Level, s string) string { return t.paint(marks[level].color, s) }

func Badge(s string) string {
	if os.Getenv("NO_COLOR") != "" {
		return s
	}
	return badge + " " + s + " " + reset
}

func (t *Writer) Header(parts ...string) {
	if len(parts) > 0 {
		parts[0] = t.paint(bold, parts[0])
	}
	_, _ = io.WriteString(t.w, t.paint(dim, "doriath · ")+strings.Join(parts, t.paint(dim, " · "))+"\n")
}

func (t *Writer) Line(level Level, text string) {
	m := marks[level]
	first, rest, _ := strings.Cut(strings.TrimRight(text, "\n"), "\n")
	_, _ = io.WriteString(t.w, t.indent+"  "+t.paint(m.color, m.mark)+" "+first+"\n")
	if rest != "" {
		for _, l := range strings.Split(rest, "\n") {
			_, _ = io.WriteString(t.w, t.indent+"      "+t.paint(dim, l)+"\n")
		}
	}
}

func (t *Writer) Section(title string) *Writer {
	_, _ = io.WriteString(t.w, t.indent+"  "+t.paint(bold, title)+"\n")
	inner := *t
	inner.indent += "  "
	return &inner
}

func (t *Writer) Problem(text string) {
	_, _ = io.WriteString(t.w, t.paint(red, "doriath:")+" "+text+"\n")
}

func (t *Writer) Lines(level Level) io.Writer {
	return &lines{t: t, level: level}
}

type lines struct {
	t     *Writer
	level Level
	mu    sync.Mutex
	buf   []byte
}

func (l *lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, p...)
	for {
		i := bytes.IndexByte(l.buf, '\n')
		if i < 0 {
			return len(p), nil
		}
		l.t.Line(l.level, string(l.buf[:i]))
		l.buf = l.buf[i+1:]
	}
}

type Bar struct {
	t     *Writer
	drawn bool
}

func (t *Writer) Bar() *Bar { return &Bar{t: t} }

const barWidth = 20

func (b *Bar) Show(done float64, text string) {
	if !b.t.tty {
		return
	}
	done = min(max(done, 0), 1)
	full := int(done * barWidth)
	head := fmt.Sprintf("%3d%% ", int(done*100))
	if cols := Width(b.t.w); cols > 0 {
		text = cut(text, cols-1-len("  ")-barWidth-len(" ")-len(head))
	}
	bar := b.t.paint(cyan, strings.Repeat("━", full)) + b.t.paint(dim, strings.Repeat("━", barWidth-full))
	_, _ = io.WriteString(b.t.w, "\r\x1b[2K  "+bar+" "+head+text)
	b.drawn = true
}

func (b *Bar) Clear() {
	if b.drawn {
		_, _ = io.WriteString(b.t.w, "\r\x1b[2K")
		b.drawn = false
	}
}

func cut(s string, n int) string {
	r := []rune(s)
	if n <= 0 {
		return ""
	}
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
