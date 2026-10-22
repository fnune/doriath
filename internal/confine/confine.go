// Package confine applies, to a process that joins a running jail from
// outside, the restrictions bubblewrap gave the jail's own processes: no
// capabilities and the jail's seccomp filter. Both are per-thread state, so
// callers lock the OS thread and exec right after.
package confine

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// DropCapabilities empties every capability set of the calling thread. A
// process that enters the jail's user namespace with nsenter holds all
// capabilities there, which bubblewrap never gives the jail's processes.
//
// A process that keeps your UID in the jail already lost its capabilities
// when it executed doriath, and may not change its bounding set any more.
// Nothing can raise them again once no_new_privs is set, so then there is
// nothing left to drop.
func DropCapabilities() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var held [2]unix.CapUserData
	if err := unix.Capget(&hdr, &held[0]); err != nil {
		return fmt.Errorf("read capabilities: %w", err)
	}
	if held[0].Effective == 0 && held[1].Effective == 0 && held[0].Permitted == 0 && held[1].Permitted == 0 {
		return nil
	}
	last, err := lastCap()
	if err != nil {
		return err
	}
	for c := 0; c <= last; c++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("drop capability %d from the bounding set: %w", c, err)
		}
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("clear ambient capabilities: %w", err)
	}
	var none [2]unix.CapUserData
	if err := unix.Capset(&hdr, &none[0]); err != nil {
		return fmt.Errorf("clear capabilities: %w", err)
	}
	return nil
}

func lastCap() (int, error) {
	data, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return 0, fmt.Errorf("read the last capability: %w", err)
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// InstallSeccomp loads a classic BPF program, in the little-endian
// sock_filter layout that internal/seccomp writes for bubblewrap, as the
// calling thread's seccomp filter.
func InstallSeccomp(prog []byte) error {
	const size = 8
	if len(prog) == 0 || len(prog)%size != 0 {
		return fmt.Errorf("seccomp program of %d bytes is not a whole number of instructions", len(prog))
	}
	filter := make([]unix.SockFilter, len(prog)/size)
	for i := range filter {
		b := prog[i*size:]
		filter[i] = unix.SockFilter{
			Code: binary.LittleEndian.Uint16(b[0:]),
			Jt:   b[2],
			Jf:   b[3],
			K:    binary.LittleEndian.Uint32(b[4:]),
		}
	}
	fprog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&fprog)), 0, 0); err != nil {
		return fmt.Errorf("install seccomp filter: %w", err)
	}
	return nil
}
