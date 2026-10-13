package proxy

import (
	"bufio"
	"net"
	"sync"
)

// prefixed returns conn with any bytes the HTTP server already buffered put
// back in front, so that a client that sends its TLS hello right after the
// CONNECT line loses nothing.
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
	return c.Conn.Close()
}

// oneConnListener hands out a single connection, then blocks until that
// connection closes, so that http.Server.Serve returns when the client is
// done.
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
