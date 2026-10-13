package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Identity is the program that opened a proxy connection, as far as girdle
// can tell. Exe is empty when it is unknown.
type Identity struct {
	PID int
	Exe string
}

type identityKey struct{}

func withIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

func IdentityFrom(ctx context.Context) Identity {
	id, _ := ctx.Value(identityKey{}).(Identity)
	return id
}

// PeerResolver answers questions about processes on the host.
type PeerResolver interface {
	// TrustsHeader reports whether pid is girdle's own init inside the jail,
	// which forwards connections for other programs and names them in a
	// header.
	TrustsHeader(pid int) bool
	Exe(pid int) string
}

// IdentifyingListener learns who is on the other end of each unix
// connection. The kernel names the connecting process. When that process is
// girdle's init, which bridges connections from inside the jail, a header
// it sends names the real caller; a header from anyone else is not read.
type IdentifyingListener struct {
	net.Listener
	Peers PeerResolver
}

const headerPrefix = "GIRDLE-PEER "

func (l *IdentifyingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	pid, err := peerPID(conn)
	if err != nil {
		return &identifiedConn{Conn: conn}, nil
	}
	if !l.Peers.TrustsHeader(pid) {
		return &identifiedConn{Conn: conn, id: Identity{PID: pid, Exe: l.Peers.Exe(pid)}}, nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	_ = conn.SetReadDeadline(time.Time{})
	id, ok := parsePeerHeader(line)
	if err != nil || !ok {
		_ = conn.Close()
		return &identifiedConn{Conn: closedConn{conn}}, nil
	}
	return &identifiedConn{Conn: prefixed(conn, r), id: id}, nil
}

func parsePeerHeader(line string) (Identity, bool) {
	data, ok := strings.CutPrefix(line, headerPrefix)
	if !ok {
		return Identity{}, false
	}
	var peer struct {
		PID int    `json:"pid"`
		Exe string `json:"exe"`
	}
	_ = json.Unmarshal([]byte(data), &peer)
	return Identity{PID: peer.PID, Exe: peer.Exe}, true
}

type identifiedConn struct {
	net.Conn
	id Identity
}

func (c *identifiedConn) Unwrap() net.Conn { return c.Conn }

type closedConn struct{ net.Conn }

func (closedConn) Read([]byte) (int, error) { return 0, errors.New("closed") }

func connIdentity(c net.Conn) Identity {
	if ic, ok := c.(*identifiedConn); ok {
		return ic.id
	}
	return Identity{}
}

func peerPID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return int(cred.Pid), nil
}
