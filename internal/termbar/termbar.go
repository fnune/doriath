// Package termbar runs a program on a pty one row shorter than your
// terminal, and draws a bar of doriath's own on the last row. A scroll
// region keeps the program's output above the bar, so the terminal keeps
// its own scrollback, selection and mouse.
package termbar

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/fnune/doriath/internal/term"
)

const (
	saveCursor    = "\x1b7"
	restoreCursor = "\x1b8"
	resetRegion   = "\x1b[r"
	clearLine     = "\x1b[2K"
	originOff     = "\x1b[?6l"
	offLastRow    = "\n\x1b[A"
)

const minRows = 3

const drainTimeout = time.Second

type Bar struct {
	in, out *os.File
	master  *os.File
	tty     *os.File
	saved   *unix.Termios
	winch   chan os.Signal
	drained chan struct{}
	closed  sync.Once
	err     error

	mu    sync.Mutex
	scan  scanner
	cols  int
	text  string
	dirty bool
	buf   bytes.Buffer
}

// Open puts your terminal in raw mode and reserves its last row. It
// returns nil when in or out is not a terminal, or when the terminal is
// too small for a bar.
func Open(in, out *os.File) (*Bar, error) {
	saved, err := unix.IoctlGetTermios(int(in.Fd()), unix.TCGETS)
	if err != nil {
		return nil, nil
	}
	ws, err := unix.IoctlGetWinsize(int(out.Fd()), unix.TIOCGWINSZ)
	if err != nil || ws.Row < minRows {
		return nil, nil
	}
	master, tty, err := openPty()
	if err != nil {
		return nil, err
	}
	if err := unix.IoctlSetTermios(int(tty.Fd()), unix.TCSETS, saved); err != nil {
		_ = master.Close()
		_ = tty.Close()
		return nil, fmt.Errorf("copy terminal settings to the pty: %w", err)
	}
	raw := *saved
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN], raw.Cc[unix.VTIME] = 1, 0
	if err := unix.IoctlSetTermios(int(in.Fd()), unix.TCSETS, &raw); err != nil {
		_ = master.Close()
		_ = tty.Close()
		return nil, fmt.Errorf("set raw mode: %w", err)
	}
	b := &Bar{in: in, out: out, master: master, tty: tty, saved: saved, winch: make(chan os.Signal, 1), drained: make(chan struct{})}
	signal.Notify(b.winch, syscall.SIGWINCH)
	b.mu.Lock()
	b.resize(ws)
	b.mu.Unlock()
	return b, nil
}

func openPty() (master, tty *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open a pty: %w", err)
	}
	fd := int(master.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		_ = master.Close()
		return nil, nil, fmt.Errorf("unlock the pty: %w", err)
	}
	n, err := unix.IoctlGetUint32(fd, unix.TIOCGPTN)
	if err != nil {
		_ = master.Close()
		return nil, nil, fmt.Errorf("name the pty: %w", err)
	}
	tty, err = os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(n), 10), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		_ = master.Close()
		return nil, nil, fmt.Errorf("open the pty: %w", err)
	}
	return master, tty, nil
}

// Start runs cmd on the pty, as the leader of a new session with the pty
// as its controlling terminal.
func (b *Bar) Start(cmd *exec.Cmd) error {
	cmd.Stdin, cmd.Stdout, cmd.Stderr = b.tty, b.tty, b.tty
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid, cmd.SysProcAttr.Setctty, cmd.SysProcAttr.Ctty = true, true, 0
	err := cmd.Start()
	_ = b.tty.Close()
	if err != nil {
		close(b.drained)
		return err
	}
	go func() { _, _ = io.Copy(b.master, b.in) }()
	go b.copyOutput()
	go b.followSize()
	return nil
}

// Set shows text on the bar.
func (b *Bar) Set(text string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if text == b.text {
		return
	}
	b.text, b.dirty = text, true
	b.flush()
}

// Close gives the terminal back as it was, except for the program's
// output.
func (b *Bar) Close() error {
	b.closed.Do(func() { b.err = b.close() })
	return b.err
}

func (b *Bar) close() error {
	select {
	case <-b.drained:
	case <-time.After(drainTimeout):
	}
	signal.Stop(b.winch)
	close(b.winch)
	b.mu.Lock()
	defer b.mu.Unlock()
	ws, err := unix.IoctlGetWinsize(int(b.out.Fd()), unix.TIOCGWINSZ)
	rows := b.scan.rows
	if err == nil {
		rows = int(ws.Row)
	}
	_, werr := io.WriteString(b.out, saveCursor+resetRegion+cursorTo(rows)+clearLine+restoreCursor)
	return errors.Join(werr, unix.IoctlSetTermios(int(b.in.Fd()), unix.TCSETS, b.saved), b.master.Close())
}

func (b *Bar) copyOutput() {
	defer close(b.drained)
	p := make([]byte, 32*1024)
	for {
		n, err := b.master.Read(p)
		if n > 0 {
			b.mu.Lock()
			b.scan.feed(p[:n], &b.buf)
			if b.scan.barErased {
				b.scan.barErased, b.dirty = false, true
			}
			b.flush()
			b.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func (b *Bar) followSize() {
	for range b.winch {
		ws, err := unix.IoctlGetWinsize(int(b.out.Fd()), unix.TIOCGWINSZ)
		if err != nil || ws.Row < minRows {
			continue
		}
		b.mu.Lock()
		b.resize(ws)
		b.mu.Unlock()
	}
}

func (b *Bar) resize(ws *unix.Winsize) {
	b.scan.rows, b.cols = int(ws.Row), int(ws.Col)
	b.buf.WriteString(saveCursor + resetRegion + restoreCursor + offLastRow)
	b.dirty = true
	b.flush()
	child := *ws
	child.Row--
	_ = unix.IoctlSetWinsize(int(b.master.Fd()), unix.TIOCSWINSZ, &child)
}

func (b *Bar) flush() {
	if b.dirty && b.scan.idle() {
		b.buf.WriteString(saveCursor + "\x1b[1;" + strconv.Itoa(b.scan.rows-1) + "r" + originOff + cursorTo(b.scan.rows) + clearLine + b.render() + restoreCursor)
		b.dirty = false
	}
	if b.buf.Len() > 0 {
		_, _ = b.out.Write(b.buf.Bytes())
		b.buf.Reset()
	}
}

func (b *Bar) render() string {
	if b.text == "" {
		return ""
	}
	text := b.text
	if room := b.cols - 2; utf8.RuneCountInString(text) > room {
		text = string([]rune(text)[:max(room-1, 0)]) + "…"
	}
	return term.Badge(text)
}

func cursorTo(row int) string { return "\x1b[" + strconv.Itoa(row) + ";1H" }
