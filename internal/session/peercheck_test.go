package session

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestControlSocketRefusesAPeerInANestedPidNamespace(t *testing.T) {
	proc := t.TempDir()
	for pid, status := range map[string]string{
		"10": "Name:\tdoriath\nNSpid:\t10\n",
		"20": "Name:\tagent\nNSpid:\t20\t3\n",
		"30": "Name:\tagent\n",
	} {
		if err := os.MkdirAll(filepath.Join(proc, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(proc, pid, "status"), []byte(status), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := requireHostNamespace(proc, 10); err != nil {
		t.Errorf("a host process: %v", err)
	}
	if err := requireHostNamespace(proc, 20); !errors.Is(err, errPeerInJail) {
		t.Errorf("a process in a nested namespace: %v", err)
	}
	if err := requireHostNamespace(proc, 30); err == nil {
		t.Error("a status without NSpid is accepted")
	}
	if err := requireHostNamespace(proc, 40); err == nil {
		t.Error("a process that is gone is accepted")
	}
}
