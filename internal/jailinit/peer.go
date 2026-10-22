package jailinit

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Peer is the process on the other end of a connection accepted inside the
// jail.
type Peer struct {
	PID int    `json:"pid"`
	Exe string `json:"exe"`
}

// PeerHeader prefixes a forwarded connection, so the proxy outside the jail
// learns which program opened it. The proxy only believes it from this init
// process, which it identifies through the kernel.
func PeerHeader(p Peer) []byte {
	data, _ := json.Marshal(p)
	return append(append([]byte("DORIATH-PEER "), data...), '\n')
}

// FindPeer finds the process that owns the client end of a loopback TCP
// connection: its socket inode in /proc/net/tcp, then the process holding a
// file descriptor for that inode.
func FindPeer(procRoot string, conn net.Conn) (Peer, error) {
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return Peer{}, fmt.Errorf("not a TCP connection")
	}
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return Peer{}, fmt.Errorf("not a TCP connection")
	}
	inode, err := socketInode(procRoot, remote, local)
	if err != nil {
		return Peer{}, err
	}
	pids, err := inodeOwners(procRoot, inode)
	if err != nil {
		return Peer{}, err
	}
	return soleOwner(procRoot, pids)
}

func soleOwner(procRoot string, pids []int) (Peer, error) {
	var first os.FileInfo
	for _, pid := range pids {
		exe := filepath.Join(procRoot, strconv.Itoa(pid), "exe")
		info, err := os.Stat(exe)
		if err != nil {
			return Peer{}, fmt.Errorf("read executable of pid %d: %w", pid, err)
		}
		if first == nil {
			first = info
		} else if !os.SameFile(first, info) {
			return Peer{}, fmt.Errorf("processes %v running different programs share the socket", pids)
		}
	}
	exe, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pids[0]), "exe"))
	if err != nil {
		return Peer{}, fmt.Errorf("read executable of pid %d: %w", pids[0], err)
	}
	return Peer{PID: pids[0], Exe: exe}, nil
}

func socketInode(procRoot string, client, server *net.TCPAddr) (string, error) {
	want := procAddr(client) + " " + procAddr(server)
	for _, table := range []string{"net/tcp", "net/tcp6"} {
		f, err := os.Open(filepath.Join(procRoot, table))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 10 {
				continue
			}
			if strings.EqualFold(fields[1]+" "+fields[2], want) || strings.EqualFold(fields[1]+" "+fields[2], procAddr6(client)+" "+procAddr6(server)) {
				_ = f.Close()
				return fields[9], nil
			}
		}
		_ = f.Close()
	}
	return "", fmt.Errorf("no socket for %s", client)
}

func procAddr(a *net.TCPAddr) string {
	ip := a.IP.To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%02X%02X%02X%02X:%04X", ip[3], ip[2], ip[1], ip[0], a.Port)
}

func procAddr6(a *net.TCPAddr) string {
	ip := a.IP.To16()
	if ip == nil {
		return ""
	}
	var b strings.Builder
	for i := 0; i < 16; i += 4 {
		b.WriteString(strings.ToUpper(hex.EncodeToString([]byte{ip[i+3], ip[i+2], ip[i+1], ip[i]})))
	}
	return fmt.Sprintf("%s:%04X", b.String(), a.Port)
}

func inodeOwners(procRoot, inode string) ([]int, error) {
	target := "socket:[" + inode + "]"
	self := os.Getpid()
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		fdDir := filepath.Join(procRoot, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if link, err := os.Readlink(filepath.Join(fdDir, fd.Name())); err == nil && link == target {
				pids = append(pids, pid)
				break
			}
		}
	}
	if len(pids) == 0 {
		return nil, fmt.Errorf("no process owns socket %s", inode)
	}
	return pids, nil
}
