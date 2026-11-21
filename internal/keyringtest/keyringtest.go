// Package keyringtest holds a keyring in memory, for tests.
package keyringtest

import (
	"sync"

	"github.com/fnune/doriath/internal/secret"
)

type Memory struct {
	mu      sync.Mutex
	entries map[string]string
	// Err is what every call returns, to stand for a keyring that does not answer.
	Err error
}

func New() *Memory { return &Memory{entries: map[string]string{}} }

func (m *Memory) Read(profile, name string) (secret.Value, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return secret.Value{}, m.Err
	}
	v, ok := m.entries[profile+"/"+name]
	if !ok {
		return secret.Value{}, secret.ErrNotInKeyring
	}
	return secret.NewValue([]byte(v)), nil
}

func (m *Memory) Write(profile, name string, v secret.Value) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return m.Err
	}
	m.entries[profile+"/"+name] = string(v.Reveal())
	return nil
}

func (m *Memory) Has(profile, name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.entries[profile+"/"+name]
	return ok
}
