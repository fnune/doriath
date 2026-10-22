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

// Backend is the configuration for one secret: a file, a command, or an
// OAuth login that doriath refreshes.
type Backend struct {
	File    string
	Command []string
	OAuth   *OAuth
}

// OAuth is a login you complete once with doriath login. The server either is
// an MCP server, which tells doriath where to sign in and lets it register,
// or names an issuer and the client doriath signs in as.
type OAuth struct {
	MCP      string
	Issuer   string
	ClientID string
	Scopes   []string
}

func (b Backend) Validate() error {
	set := 0
	for _, ok := range []bool{b.File != "", len(b.Command) > 0, b.OAuth != nil} {
		if ok {
			set++
		}
	}
	if set != 1 {
		return errors.New("set exactly one of file, command or oauth")
	}
	if o := b.OAuth; o != nil {
		switch {
		case (o.MCP == "") == (o.Issuer == ""):
			return errors.New("oauth: set mcp or issuer")
		case o.Issuer != "" && o.ClientID == "":
			return errors.New("oauth: an issuer needs the client_id doriath signs in as")
		case o.MCP != "" && o.ClientID != "":
			return errors.New("oauth: an MCP server registers doriath itself; leave out client_id")
		}
		for _, u := range []string{o.MCP, o.Issuer} {
			if u != "" && !strings.HasPrefix(u, "https://") {
				return fmt.Errorf("oauth: %q: want an https URL", u)
			}
		}
	}
	return nil
}

// OAuthTokens returns a current access token for an OAuth secret, refreshing
// it when it has expired.
type OAuthTokens interface {
	Token(ctx context.Context, name string, o OAuth) (Value, error)
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

	oauth OAuthTokens

	mu    sync.Mutex
	cache map[string]Value
}

// WithOAuth lets the store serve OAuth secrets.
func (c *Configured) WithOAuth(t OAuthTokens) *Configured {
	c.oauth = t
	return c
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
	if b.OAuth != nil {
		if c.oauth == nil {
			return Value{}, fmt.Errorf("secret %q: OAuth logins are not available here", name)
		}
		return c.oauth.Token(ctx, name, *b.OAuth)
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
