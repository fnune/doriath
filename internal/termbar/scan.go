package termbar

import (
	"bytes"
	"math"
	"strconv"
	"strings"
)

const (
	ground = iota
	escape
	escapeOverflow
	csi
	csiOverflow
	str
	strEscape
)

const maxSequence = 256

type scanner struct {
	rows          int
	state         int
	seq           []byte
	utf8Remaining int
	barErased     bool
}

func (s *scanner) idle() bool { return s.state == ground && s.utf8Remaining == 0 }

func (s *scanner) feed(p []byte, out *bytes.Buffer) {
	for _, b := range p {
		s.step(b, out)
	}
}

func (s *scanner) step(b byte, out *bytes.Buffer) {
	if b == 0x1b && (s.state == csi || s.state == csiOverflow || s.state == escapeOverflow) {
		if s.state == csi {
			out.Write(s.seq)
		}
		s.state, s.seq = escape, append(s.seq[:0], b)
		return
	}
	switch s.state {
	case ground:
		if b == 0x1b {
			s.state, s.seq, s.utf8Remaining = escape, append(s.seq[:0], b), 0
			return
		}
		switch {
		case b >= 0xc0:
			s.utf8Remaining = utf8Continuations(b)
		case b >= 0x80 && s.utf8Remaining > 0:
			s.utf8Remaining--
		case b >= 0x80 && b <= 0x9f:
			return
		default:
			s.utf8Remaining = 0
		}
		out.WriteByte(b)
	case escape:
		s.seq = append(s.seq, b)
		switch {
		case b == '[':
			s.state = csi
		case b == ']' || b == 'P' || b == '_' || b == '^' || b == 'X':
			out.Write(s.seq)
			s.state = str
		case b == 0x1b:
			out.Write(s.seq[:len(s.seq)-1])
			s.seq = s.seq[:1]
		case b >= 0x20 && b <= 0x2f:
			if len(s.seq) > maxSequence {
				s.state = escapeOverflow
			}
		default:
			out.Write(s.seq)
			s.state = ground
			if b == 'c' && len(s.seq) == 2 {
				s.barErased = true
				out.WriteString(s.region())
			}
		}
	case escapeOverflow:
		if b < 0x20 || b > 0x2f {
			s.state = ground
		}
	case csi:
		s.seq = append(s.seq, b)
		switch {
		case b >= 0x40 && b <= 0x7e:
			out.Write(s.rewriteCSI(s.seq))
			s.state = ground
		case b == 0x18 || b == 0x1a:
			out.Write(s.seq)
			s.state = ground
		case len(s.seq) > maxSequence:
			s.state = csiOverflow
		}
	case csiOverflow:
		if b >= 0x40 && b <= 0x7e || b == 0x18 || b == 0x1a {
			s.state = ground
		}
	case str:
		if b == 0x1b {
			s.state = strEscape
			return
		}
		out.WriteByte(b)
		if b == 0x07 {
			s.state = ground
		}
	case strEscape:
		if b == '\\' {
			out.WriteString("\x1b\\")
			s.state = ground
			return
		}
		s.state, s.seq = escape, append(s.seq[:0], 0x1b)
		s.step(b, out)
	}
}

func utf8Continuations(b byte) int {
	switch {
	case b >= 0xf0:
		return 3
	case b >= 0xe0:
		return 2
	default:
		return 1
	}
}

func (s *scanner) rewriteCSI(seq []byte) []byte {
	final := seq[len(seq)-1]
	body := string(seq[2 : len(seq)-1])
	private := body != "" && strings.ContainsRune("<=>?", rune(body[0]))
	intermediate := strings.TrimLeft(body, "0123456789:;<=>?")
	params := strings.Split(strings.TrimRight(strings.TrimLeft(body, "<=>?"), intermediate), ";")
	last := s.rows - 1
	switch {
	case private && (final == 'h' || final == 'l'):
		for _, p := range params {
			if p == "1049" || p == "1047" || p == "47" {
				s.barErased = true
			}
		}
	case private:
	case intermediate == "!" && final == 'p':
		s.barErased = true
		return []byte(string(seq) + s.region())
	case intermediate != "":
	case final == 'r':
		top := param(params, 0, 1)
		bottom := param(params, 1, last)
		if bottom > last {
			bottom = last
		}
		return []byte("\x1b[" + strconv.Itoa(top) + ";" + strconv.Itoa(bottom) + "r")
	case final == 'H' || final == 'f':
		if param(params, 0, 1) > last {
			return []byte("\x1b[" + strconv.Itoa(last) + ";" + strconv.Itoa(param(params, 1, 1)) + string(final))
		}
	case final == 'd':
		if param(params, 0, 1) > last {
			return []byte("\x1b[" + strconv.Itoa(last) + "d")
		}
	case final == 'J':
		if p := param(params, 0, 0); p == 0 || p == 2 {
			s.barErased = true
		}
	}
	return seq
}

func (s *scanner) region() string {
	return saveCursor + "\x1b[1;" + strconv.Itoa(s.rows-1) + "r" + restoreCursor
}

func param(params []string, n, def int) int {
	if n >= len(params) {
		return def
	}
	v := 0
	for _, part := range strings.Split(params[n], ":") {
		digits := strings.TrimLeft(part, "0")
		if digits == "" || strings.Trim(digits, "0123456789") != "" {
			continue
		}
		p, err := strconv.Atoi(digits)
		if err != nil || len(digits) > 9 {
			p = math.MaxInt32
		}
		v = max(v, p)
	}
	if v == 0 {
		return def
	}
	return v
}
