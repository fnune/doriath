package jailinit

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func FuzzProcAddr(f *testing.F) {
	f.Add([]byte{127, 0, 0, 1}, uint16(8080))
	f.Add([]byte(net.ParseIP("::1")), uint16(443))
	f.Add([]byte(net.ParseIP("::ffff:10.0.0.1")), uint16(0))
	f.Fuzz(func(t *testing.T, ip []byte, port uint16) {
		if len(ip) != 4 && len(ip) != 16 {
			return
		}
		a := &net.TCPAddr{IP: ip, Port: int(port)}
		if v4 := a.IP.To4(); v4 != nil {
			got := decodeProcAddr(t, procAddr(a))
			if !got.IP.Equal(v4) || got.Port != a.Port {
				t.Fatalf("%s reads back as %s", a, got)
			}
		}
		got := decodeProcAddr(t, procAddr6(a))
		if !got.IP.Equal(a.IP) || got.Port != a.Port {
			t.Fatalf("%s reads back as %s", a, got)
		}
	})
}

func decodeProcAddr(t *testing.T, s string) *net.TCPAddr {
	t.Helper()
	host, port, ok := strings.Cut(s, ":")
	raw, err := hex.DecodeString(host)
	if !ok || err != nil || (len(raw) != 4 && len(raw) != 16) {
		t.Fatalf("%q is not a /proc/net/tcp address", s)
	}
	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(ip[i:], binary.LittleEndian.Uint32(raw[i:]))
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil || len(port) != 4 {
		t.Fatalf("%q has no 16-bit port", s)
	}
	return &net.TCPAddr{IP: ip, Port: int(p)}
}

func FuzzSocketInode(f *testing.F) {
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	client := "   0: 0100007F:A1B2 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 111 1 0 20 4 30 10 -1\n"
	server := "   1: 0100007F:1F90 0100007F:A1B2 01 00000000:00000000 00:00000000 00000000  1000        0 222 1 0 20 4 30 10 -1\n"
	f.Add(header+server+client, uint16(0xA1B2), uint16(0x1F90))
	f.Add(header+server, uint16(0xA1B2), uint16(0x1F90))
	f.Add(header+strings.ToLower(client), uint16(0xA1B2), uint16(0x1F90))
	f.Add(header+"0: 0100007F:A1B2 0100007F:1F90\n", uint16(0xA1B2), uint16(0x1F90))
	root := f.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o700); err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, table string, clientPort, serverPort uint16) {
		if clientPort == serverPort {
			return
		}
		if err := os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(table), 0o600); err != nil {
			t.Fatal(err)
		}
		c := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(clientPort)}
		s := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(serverPort)}
		inode, err := socketInode(root, c, s)
		if err != nil {
			return
		}
		for _, line := range strings.Split(table, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 10 && fields[9] == inode && strings.EqualFold(fields[1], procAddr(c)) && strings.EqualFold(fields[2], procAddr(s)) {
				return
			}
		}
		t.Fatalf("inode %s does not belong to the client's end of %s -> %s", inode, c, s)
	})
}
