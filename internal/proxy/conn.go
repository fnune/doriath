package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"
)

func prefixed(conn net.Conn, buf *bufio.Reader) net.Conn {
	if buf == nil || buf.Buffered() == 0 {
		return conn
	}
	return &bufferedConn{Conn: conn, r: buf}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

type oneConnListener struct {
	conn     net.Conn
	accepted sync.Once
	closing  sync.Once
	closed   chan struct{}
}

func newOneConnListener(c net.Conn) *oneConnListener {
	l := &oneConnListener{closed: make(chan struct{})}
	l.conn = &notifyConn{Conn: c, onClose: func() { l.closeOnce() }}
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.accepted.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *oneConnListener) closeOnce() {
	l.closing.Do(func() { close(l.closed) })
}

func (l *oneConnListener) Close() error {
	l.closeOnce()
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type notifyConn struct {
	net.Conn
	mu      sync.Mutex
	onClose func()
}

func (c *notifyConn) Close() error {
	err := c.Conn.Close()
	c.mu.Lock()
	if c.onClose != nil {
		c.onClose()
		c.onClose = nil
	}
	c.mu.Unlock()
	return err
}

// peekServerName reads a TLS ClientHello far enough to learn its server
// name, so that a tunnel to an allowed host cannot carry a handshake for
// another name served from the same address. It returns the bytes it read,
// which the caller sends on. A client that is not speaking TLS, or sends no
// name, yields an empty name.
func peekServerName(conn net.Conn) (string, []byte) {
	_ = conn.SetReadDeadline(time.Now().Add(helloTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	rec := &recordingConn{Conn: conn}
	var name string
	_ = tls.Server(rec, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			name = hello.ServerName
			return nil, errHelloRead
		},
	}).Handshake()
	return name, rec.read.Bytes()
}

// helloTimeout bounds the wait for a ClientHello. TLS clients send it at
// once; a protocol where the server speaks first waits this long, then
// passes through unchecked.
const helloTimeout = 3 * time.Second

var errHelloRead = errors.New("client hello read")

// recordingConn keeps what it reads and drops what it writes, so a TLS
// server can parse a ClientHello without answering the client.
type recordingConn struct {
	net.Conn
	read bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Write(p[:n])
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error) { return len(p), nil }
