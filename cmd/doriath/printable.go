package main

import (
	"bytes"
	"io"

	"github.com/fnune/doriath/internal/session"
)

type printableWriter struct {
	w   io.Writer
	buf []byte
}

func printableLines(w io.Writer) io.Writer { return &printableWriter{w: w} }

func (p *printableWriter) Write(data []byte) (int, error) {
	p.buf = append(p.buf, data...)
	for {
		i := bytes.IndexByte(p.buf, '\n')
		if i < 0 {
			return len(data), nil
		}
		line := session.Printable(string(p.buf[:i]))
		p.buf = p.buf[i+1:]
		if _, err := io.WriteString(p.w, line+"\n"); err != nil {
			return 0, err
		}
	}
}
