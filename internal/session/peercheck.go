package session

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type outsideJailListener struct {
	net.Listener
	procRoot string
	refused  func(pid int, err error)
}

func (l outsideJailListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		pid, err := peerPID(conn)
		if err == nil {
			err = requireHostNamespace(l.procRoot, pid)
		}
		if err == nil {
			return conn, nil
		}
		_ = conn.Close()
		if l.refused != nil {
			l.refused(pid, err)
		}
	}
}

func peerPID(conn net.Conn) (int, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a unix connection")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) { cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return int(cred.Pid), nil
}

var errPeerInJail = errors.New("the peer runs in a pid namespace below the host's")

func requireHostNamespace(procRoot string, pid int) error {
	status, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return err
	}
	for line := range strings.SplitSeq(string(status), "\n") {
		if rest, ok := strings.CutPrefix(line, "NSpid:"); ok {
			if len(strings.Fields(rest)) > 1 {
				return errPeerInJail
			}
			return nil
		}
	}
	return errors.New("the status of the peer has no NSpid line")
}
