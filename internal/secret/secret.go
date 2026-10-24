// Package secret resolves named secrets from the user's configured backends.
package secret

import (
	"bytes"
	"context"
	"encoding/json"
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

// ErrUnavailable wraps the last failure of a secret that doriath could not
// read yet, until the next try is due.
var ErrUnavailable = errors.New("unavailable")

// Backend is the configuration for one secret: a file, a command, or an
// OAuth login that doriath refreshes.
type Backend struct {
	File    string
	Command []string
	OAuth   *OAuth
	// Refresh reads a file or command secret again after this long, for a
	// short-lived token whose source prints no expiry.
	Refresh time.Duration
	// Required stops a session from starting without the secret. Without
	// it, the session starts and what needs the secret fails until the
	// secret works.
	Required bool `json:"-"`
}

// OAuth is a login you complete once with doriath profiles login. The server either is
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
	switch {
	case b.Refresh != 0 && b.OAuth != nil:
		return errors.New("refresh: an OAuth login refreshes on its own")
	case b.Refresh != 0 && b.Refresh < MinRefresh:
		return fmt.Errorf("refresh: want %s or more", MinRefresh)
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

// Command is one run of a secret's command. With Terminal, the command may
// ask you for a password there. A refresh during the session never gets the
// terminal, which the agent uses.
type Command struct {
	Secret   string
	Argv     []string
	Terminal bool
}

type Runner interface {
	Output(ctx context.Context, c Command) (stdout, stderr []byte, err error)
}

type FileReader interface {
	Stat(path string) (fs.FileInfo, error)
	ReadFile(path string) ([]byte, error)
}

const commandTimeout = 2 * time.Minute

const (
	MinRefresh              = time.Minute
	refreshEarly            = 5 * time.Minute
	retryFailedRefreshAfter = 30 * time.Second
)

// Configured fetches each secret from its backend and keeps it in memory,
// so a session asks for a secret once and not on every request. A secret
// that expires, or that the profile refreshes, is read again when it is
// due.
type Configured struct {
	backends map[string]Backend
	run      Runner
	files    FileReader
	now      func() time.Time

	oauth OAuthTokens

	mu     sync.Mutex
	cache  map[string]cached
	failed map[string]failure
}

type unavailableError struct{ err error }

func (e unavailableError) Error() string        { return e.err.Error() }
func (e unavailableError) Unwrap() error        { return e.err }
func (e unavailableError) Is(target error) bool { return target == ErrUnavailable }

type failure struct {
	err     error
	retryAt time.Time
}

type cached struct {
	value        Value
	due, expires time.Time
}

// WithOAuth lets the store serve OAuth secrets.
func (c *Configured) WithOAuth(t OAuthTokens) *Configured {
	c.oauth = t
	return c
}

func NewConfigured(backends map[string]Backend, run Runner, files FileReader) *Configured {
	return &Configured{backends: backends, run: run, files: files, now: time.Now, cache: map[string]cached{}, failed: map[string]failure{}}
}

// WithClock replaces the clock that decides when a secret is due.
func (c *Configured) WithClock(now func() time.Time) *Configured {
	c.now = now
	return c
}

func (c *Configured) Get(ctx context.Context, name string) (Value, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	old, seen := c.cache[name]
	if seen && (old.due.IsZero() || now.Before(old.due)) {
		return old.value, nil
	}
	b, ok := c.backends[name]
	if !ok {
		return Value{}, fmt.Errorf("secret %q: %w: add [secrets.%s] to the profile", name, ErrUnknown, name)
	}
	if b.OAuth != nil {
		if c.oauth == nil {
			return Value{}, fmt.Errorf("secret %q: OAuth logins are not available here", name)
		}
		v, err := c.oauth.Token(ctx, name, *b.OAuth)
		if err != nil {
			c.failed[name] = failure{err: err, retryAt: now}
			return Value{}, err
		}
		delete(c.failed, name)
		return v, nil
	}
	f, failedBefore := c.failed[name]
	if !seen && failedBefore && now.Before(f.retryAt) {
		return Value{}, unavailableError{f.err}
	}
	v, err := c.fetch(ctx, name, b, !seen && !failedBefore)
	if err != nil {
		if seen && (old.expires.IsZero() || now.Before(old.expires)) {
			old.due = now.Add(retryFailedRefreshAfter)
			c.cache[name] = old
			return old.value, nil
		}
		delete(c.cache, name)
		c.failed[name] = failure{err: err, retryAt: now.Add(retryFailedRefreshAfter)}
		return Value{}, err
	}
	delete(c.failed, name)
	c.cache[name] = lifetime(v, b, now)
	return v, nil
}

// Provide sets a secret for the rest of the session, in place of what its
// source gives. doriath does not read the source again.
func (c *Configured) Provide(name string, v Value) error {
	b, ok := c.backends[name]
	if !ok {
		return fmt.Errorf("secret %q: %w: add [secrets.%s] to the profile, and start a new session", name, ErrUnknown, name)
	}
	if b.OAuth != nil {
		return fmt.Errorf("secret %q is an OAuth login: run `doriath profiles login` on the host instead", name)
	}
	if len(bytes.TrimSpace(v.b)) == 0 {
		return fmt.Errorf("secret %q is empty", name)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[name] = cached{value: v}
	delete(c.failed, name)
	return nil
}

// Retry forgets that a secret failed, so that the next Get reads its source
// at once.
func (c *Configured) Retry(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.failed, name)
}

// Unavailable returns the last error of each secret that doriath has not
// read since it failed.
func (c *Configured) Unavailable() map[string]error {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]error{}
	for name, f := range c.failed {
		out[name] = f.err
	}
	return out
}

func lifetime(v Value, b Backend, now time.Time) cached {
	e := cached{value: v}
	if b.Refresh > 0 {
		e.due = now.Add(b.Refresh)
	}
	if expires, ok := credentialProcessExpiry(v.b); ok {
		e.expires = expires
		early := min(refreshEarly, expires.Sub(now)/2)
		if due := expires.Add(-early); e.due.IsZero() || due.Before(e.due) {
			e.due = due
		}
	}
	return e
}

func credentialProcessExpiry(data []byte) (time.Time, bool) {
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		return time.Time{}, false
	}
	var doc struct {
		Expiration time.Time `json:"Expiration"`
	}
	if json.Unmarshal(data, &doc) != nil || doc.Expiration.IsZero() {
		return time.Time{}, false
	}
	return doc.Expiration, true
}

func (c *Configured) fetch(ctx context.Context, name string, b Backend, terminal bool) (Value, error) {
	if b.File != "" {
		info, err := c.files.Stat(b.File)
		if err != nil {
			return Value{}, fmt.Errorf("secret %q: %w", name, err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return Value{}, fmt.Errorf("secret %q: %s is readable by other users (mode %04o): run `chmod 600 %s`", name, b.File, info.Mode().Perm(), b.File)
		}
		data, err := c.files.ReadFile(b.File)
		if err != nil {
			return Value{}, fmt.Errorf("secret %q: %w", name, err)
		}
		return trimmed(name, data)
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	stdout, stderr, err := c.run.Output(ctx, Command{Secret: name, Argv: b.Command, Terminal: terminal})
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg != "" {
			return Value{}, fmt.Errorf("secret %q: command %s: %w: %s", name, b.Command[0], err, lastLine(msg))
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

func lastLine(s string) string {
	return s[strings.LastIndex(s, "\n")+1:]
}

type OSFiles struct{}

func (OSFiles) Stat(path string) (fs.FileInfo, error) { return os.Stat(path) }
func (OSFiles) ReadFile(path string) ([]byte, error)  { return os.ReadFile(path) }
