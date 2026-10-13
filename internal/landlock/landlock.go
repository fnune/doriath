// Package landlock limits where a process can write, without privileges.
// Only write rights are handled, so reads and execution stay governed by the
// jail's mount namespace.
package landlock

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ErrUnsupported means the kernel has no Landlock, or it is disabled.
var ErrUnsupported = errors.New("landlock not supported by this kernel")

const (
	fileWrites = unix.LANDLOCK_ACCESS_FS_WRITE_FILE
	dirWrites  = unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM
)

func ABI() (int, error) {
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		if errno == unix.ENOSYS || errno == unix.EOPNOTSUPP {
			return 0, fmt.Errorf("%w: %w", ErrUnsupported, errno)
		}
		return 0, fmt.Errorf("query landlock ABI version: %w", errno)
	}
	return int(v), nil
}

func handledRights(abi int) uint64 {
	rights := uint64(fileWrites | dirWrites)
	if abi >= 2 {
		rights |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		rights |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	return rights
}

// RestrictWrites lets the calling thread write only beneath the writable
// paths, skipping those that do not exist. Landlock binds the calling thread
// and the processes it later starts, not the other threads of a Go program,
// so call it with the OS thread locked and exec right after.
func RestrictWrites(writable []string) error {
	abi, err := ABI()
	if err != nil {
		return err
	}
	handled := handledRights(abi)
	attr := unix.LandlockRulesetAttr{Handled_access_fs: handled}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fmt.Errorf("create landlock ruleset: %w", errno)
	}
	ruleset := int(fd)
	defer func() { _ = unix.Close(ruleset) }()

	for _, path := range writable {
		if err := allowBeneath(ruleset, path, handled); err != nil {
			return err
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(ruleset), 0, 0); errno != 0 {
		return fmt.Errorf("restrict self with landlock: %w", errno)
	}
	return nil
}

func allowBeneath(ruleset int, path string, handled uint64) error {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open writable path %s: %w", path, err)
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("stat writable path %s: %w", path, err)
	}
	allowed := handled
	if isFile := st.Mode&unix.S_IFMT != unix.S_IFDIR; isFile {
		allowed &= fileWrites | unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	rule := unix.LandlockPathBeneathAttr{Allowed_access: allowed, Parent_fd: int32(fd)}
	if _, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(ruleset),
		unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&rule)), 0, 0, 0); errno != 0 {
		return fmt.Errorf("allow writes beneath %s: %w", path, errno)
	}
	return nil
}
