package session

import (
	"fmt"
	"net"
	"os"
)

func listenUnix(path string) (net.Listener, error) {
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("protect %s: %w", path, err)
	}
	return l, nil
}
