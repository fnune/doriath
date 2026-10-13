// Package secret resolves named secrets from the user's configured backends.
package secret

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"
)

// Value holds secret material. Its String method never prints the secret,
// so a Value that ends up in a log or an error message stays redacted.
type Value struct {
	b []byte
}

func NewValue(b []byte) Value { return Value{b: bytes.Clone(b)} }

func (v Value) Reveal() []byte { return bytes.Clone(v.b) }

func (v Value) String() string { return "[redacted]" }

func (v Value) GoString() string { return "secret.Value{[redacted]}" }

type Store interface {
	Get(ctx context.Context, name string) (Value, error)
}

var ErrUnknown = errors.New("unknown secret")

// Backend is the configuration for one secret: a file or a command.
type Backend struct {
	File    string
	Command []string
}

func (b Backend) Validate() error {
	switch {
	case b.File != "" && len(b.Command) > 0:
		return errors.New("set file or command, not both")
	case b.File == "" && len(b.Command) == 0:
		return errors.New("set file or command")
	}
	return nil
}

type Runner interface {
	Output(ctx context.Context, argv []string) (stdout, stderr []byte, err error)
}

type FileReader interface {
	Stat(path string) (fs.FileInfo, error)
	ReadFile(path string) ([]byte, error)
}

const commandTimeout = 2 * time.Minute

// Configured fetches each secret from its backend at most once and keeps it
// in memory, so a session asks for a secret once and not on every request.
type Configured struct {
	backends map[string]Backend
	run      Runner
	files    FileReader

	mu    sync.Mutex
	cache map[string]Value
}

func NewConfigured(backends map[string]Backend, run Runner, files FileReader) *Configured {
	return &Configured{backends: backends, run: run, files: files, cache: map[string]Value{}}
}

func (c *Configured) Get(ctx context.Context, name string) (Value, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.cache[name]; ok {
		return v, nil
	}
	b, ok := c.backends[name]
	if !ok {
		return Value{}, fmt.Errorf("secret %q: %w: add [secrets.%s] to the profile", name, ErrUnknown, name)
	}
	v, err := c.fetch(ctx, name, b)
	if err != nil {
		return Value{}, err
	}
	c.cache[name] = v
	return v, nil
}

func (c *Configured) fetch(ctx context.Context, name string, b Backend) (Value, error) {
	if b.File != "" {
		info, err := c.files.Stat(b.File)
		if err != nil {
			return Value{}, fmt.Errorf("secret %q: %w", name, err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return Value{}, fmt.Errorf("secret %q: %s is readable by other users (mode %04o): run chmod 600 on it", name, b.File, info.Mode().Perm())
		}
		data, err := c.files.ReadFile(b.File)
		if err != nil {
			return Value{}, fmt.Errorf("secret %q: %w", name, err)
		}
		return trimmed(name, data)
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	stdout, stderr, err := c.run.Output(ctx, b.Command)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg != "" {
			return Value{}, fmt.Errorf("secret %q: command %s: %w: %s", name, b.Command[0], err, firstLine(msg))
		}
		return Value{}, fmt.Errorf("secret %q: command %s: %w", name, b.Command[0], err)
	}
	return trimmed(name, stdout)
}

// trimmed drops one trailing newline, which files and command output add, but
// keeps everything else so that multi-line keys survive.
func trimmed(name string, data []byte) (Value, error) {
	data = bytes.TrimSuffix(data, []byte("\n"))
	data = bytes.TrimSuffix(data, []byte("\r"))
	if len(bytes.TrimSpace(data)) == 0 {
		return Value{}, fmt.Errorf("secret %q is empty", name)
	}
	return NewValue(data), nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

type OSFiles struct{}

func (OSFiles) Stat(path string) (fs.FileInfo, error) { return os.Stat(path) }
func (OSFiles) ReadFile(path string) ([]byte, error)  { return os.ReadFile(path) }
