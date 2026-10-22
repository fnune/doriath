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
)

const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	dim    = "\x1b[2m"
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	cyan   = "\x1b[36m"
)

var marks = map[Level]struct{ mark, color string }{
	Info:    {"·", dim},
	OK:      {"✓", green},
	Warn:    {"!", yellow},
	Problem: {"✕", red},
	Action:  {"↺", cyan},
}

type Writer struct {
	w     io.Writer
	color bool
}

func New(w io.Writer) *Writer {
	return &Writer{w: w, color: colors(w)}
}

func colors(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

func (t *Writer) paint(color, s string) string {
	if !t.color || s == "" {
		return s
	}
	return color + s + reset
}

func (t *Writer) Dim(s string) string { return t.paint(dim, s) }

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
