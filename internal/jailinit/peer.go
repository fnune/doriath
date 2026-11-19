package jailinit

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type Peer struct {
	PID int    `json:"pid"`
	Exe string `json:"exe"`
	// File is the file that the process runs, which a path alone does not
	// name: the agent can put another file at the path, or change the file
	// through another link to it.
	File FileID `json:"file,omitzero"`
	// Code lists the files that the process maps as executable, such as its
	// libraries and anything LD_PRELOAD added.
	Code     []MappedFile `json:"code,omitempty"`
	Commands []string     `json:"commands,omitempty"`
}

// MappedFile is a file in /proc/PID/maps. The device number in maps can
// differ from the one stat reports, so File comes from a stat of the path
// that still names a file with the mapped inode, and is zero otherwise.
type MappedFile struct {
	Path string `json:"path"`
	Ino  uint64 `json:"ino"`
	// Range and Offset place the mapping in the process and in the file. They
	// let the proxy read the code from the process's memory, which is the
	// only way to see a file that its program deleted after it loaded it.
	Range  string `json:"range,omitempty"`
	Offset uint64 `json:"offset,omitempty"`
	File   FileID `json:"file,omitzero"`
}

type FileID struct {
	Dev   uint64 `json:"dev"`
	Ino   uint64 `json:"ino"`
	Ctime int64  `json:"ctime"`
}

func FileIDOf(info os.FileInfo) FileID {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return FileID{}
	}
	return FileID{Dev: st.Dev, Ino: st.Ino, Ctime: st.Ctim.Nano()}
}

// PeerHeader prefixes a forwarded connection, so the proxy outside the jail
// learns which program opened it. The proxy only believes it from this init
// process, which it identifies through the kernel.
func PeerHeader(p Peer) []byte {
	data, _ := json.Marshal(p)
	return append(append([]byte("DORIATH-PEER "), data...), '\n')
}

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
	return Describe(procRoot, pids[0])
}

func Describe(procRoot string, pid int) (Peer, error) {
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	exe, err := os.Readlink(filepath.Join(dir, "exe"))
	if err != nil {
		return Peer{}, fmt.Errorf("read executable of pid %d: %w", pid, err)
	}
	peer := Peer{PID: pid, Exe: exe}
	if info, err := os.Stat(filepath.Join(dir, "exe")); err == nil {
		peer.File = FileIDOf(info)
	}
	maps, err := os.ReadFile(filepath.Join(dir, "maps"))
	if err != nil {
		return Peer{}, fmt.Errorf("read the mappings of pid %d: %w", pid, err)
	}
	peer.Code = executableMappings(maps)
	identifyMappings(dir, peer.Code)
	peer.Commands = commandChain(os.ReadFile, procRoot, pid, os.Getpid())
	return peer, nil
}

func executableMappings(maps []byte) []MappedFile {
	var out []MappedFile
	for line := range strings.SplitSeq(string(maps), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || !strings.Contains(fields[1], "x") {
			continue
		}
		path := strings.Join(fields[5:], " ")
		offset, _ := strconv.ParseUint(fields[2], 16, 64)
		if !strings.HasPrefix(path, "/") || slices.ContainsFunc(out, func(f MappedFile) bool { return f.Path == path && f.Offset == offset }) {
			continue
		}
		ino, _ := strconv.ParseUint(fields[4], 10, 64)
		out = append(out, MappedFile{Path: path, Ino: ino, Range: fields[0], Offset: offset})
	}
	return out
}

func identifyMappings(procDir string, code []MappedFile) {
	root, err := unix.Open(filepath.Join(procDir, "root"), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer func() { _ = unix.Close(root) }()
	for i, f := range code {
		if id, err := statInRoot(root, f.Path); err == nil && id.Ino == f.Ino {
			code[i].File = id
		}
	}
}

func statInRoot(root int, path string) (FileID, error) {
	fd, err := unix.Openat2(root, path, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return FileID{}, err
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return FileID{}, err
	}
	return FileID{Dev: st.Dev, Ino: st.Ino, Ctime: st.Ctim.Nano()}, nil
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
