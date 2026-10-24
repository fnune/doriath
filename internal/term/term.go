// Package term prints doriath's messages: a header, then one marked line
// per message, colored with the terminal's own palette when the output is
// a terminal and NO_COLOR is unset.
package term

import (
	"bytes"
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
	Refused: {"⊘", dim},
}

type Writer struct {
	w     io.Writer
	color bool
}

func New(w io.Writer) *Writer {
	return &Writer{w: w, color: IsTerminal(w) && os.Getenv("NO_COLOR") == ""}
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

// Title saves the terminal's window title on its title stack, sets it, and
// returns a function that puts the saved title back.
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

// Tint colors s like the mark of level.
func (t *Writer) Tint(level Level, s string) string { return t.paint(marks[level].color, s) }

// Badge sets s apart from the program around it: the text takes the
// terminal's background color on a blue field, in the terminal's own
// palette. NO_COLOR prints s as it is.
func Badge(s string) string {
	if os.Getenv("NO_COLOR") != "" {
		return s
	}
	return badge + " " + s + " " + reset
}

// Header starts a block: "doriath · " and the parts, the first one bold.
func (t *Writer) Header(parts ...string) {
	if len(parts) > 0 {
		parts[0] = t.paint(bold, parts[0])
	}
	_, _ = io.WriteString(t.w, t.paint(dim, "doriath · ")+strings.Join(parts, t.paint(dim, " · "))+"\n")
}

// Line prints one message under a header. Lines after the first, such as a
// profile snippet, are indented under it and dimmed.
func (t *Writer) Line(level Level, text string) {
	m := marks[level]
	first, rest, _ := strings.Cut(strings.TrimRight(text, "\n"), "\n")
	_, _ = io.WriteString(t.w, "  "+t.paint(m.color, m.mark)+" "+first+"\n")
	if rest != "" {
		for _, l := range strings.Split(rest, "\n") {
			_, _ = io.WriteString(t.w, "      "+t.paint(dim, l)+"\n")
		}
	}
}

// Problem prints an error on its own, outside a block.
func (t *Writer) Problem(text string) {
	_, _ = io.WriteString(t.w, t.paint(red, "doriath:")+" "+text+"\n")
}

// Lines returns a writer that prints each line written to it as a message at
// level, for code that reports through an io.Writer.
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
