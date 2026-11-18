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

	"github.com/fnune/doriath/internal/cli"
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

var ErrUnavailable = errors.New("unavailable")

type Backend struct {
	File    string
	Command []string
	Keyring bool
	OAuth   *OAuth
	// Refresh reads a file or command secret again after this long, for a
	// short-lived token whose source prints no expiry.
	Refresh time.Duration
	// Required stops a session from starting without the secret. Without
	// it, the session starts and what needs the secret fails until the
	// secret works.
	Required bool `json:"-"`
}

type OAuth struct {
	MCP      string
	Issuer   string
	ClientID string
	Scopes   []string
}

func (b Backend) Validate() error {
	set := 0
	for _, ok := range []bool{b.File != "", len(b.Command) > 0, b.Keyring, b.OAuth != nil} {
		if ok {
			set++
		}
	}
	if set != 1 {
		return errors.New("set exactly one of file, command, keyring or oauth")
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

type OAuthTokens interface {
	Token(ctx context.Context, name string, o OAuth) (Value, error)
}

// Keyring keeps the keyring secrets of each profile in the keyring of your
// desktop. Read returns ErrNotInKeyring for a secret that has no entry yet.
type Keyring interface {
	Read(profile, name string) (Value, error)
	Write(profile, name string, v Value) error
}

var ErrNotInKeyring = errors.New("not in the keyring")

type Asker interface {
	Ask(ctx context.Context, profile, name string) (Value, error)
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

	keyring Keyring
	owner   func(name string) string
	ask     Asker

	mu     sync.Mutex
	cache  map[string]cached
	failed map[string]failure
}

type unavailableError struct{ err error }

func (e unavailableError) Error() string        { return e.err.Error() }
func (e unavailableError) Unwrap() error        { return e.err }
func (e unavailableError) Is(target error) bool { return target == ErrUnavailable }

// CommandError is a secret command that failed. Its message leaves out what
// the command printed, because the message reaches the jail and a command
// can print its secret when it fails. Explained adds it back for you.
type CommandError struct {
	Secret  string
	Program string
	Err     error
	Stderr  string
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("secret %q: command %s: %v", e.Secret, e.Program, e.Err)
}

func (e *CommandError) Unwrap() error { return e.Err }

type explained struct{ err error }

func (e explained) Error() string {
	var c *CommandError
	if errors.As(e.err, &c) && c.Stderr != "" {
		return e.err.Error() + ": " + c.Stderr
	}
	return e.err.Error()
}

func (e explained) Unwrap() error { return e.err }

// Explained is err with the last line that a failed secret command printed,
// for messages that only you see.
func Explained(err error) error {
	if err == nil {
		return nil
	}
	return explained{err}
}

type failure struct {
	err     error
	retryAt time.Time
}

type cached struct {
	value        Value
	due, expires time.Time
}

func (c *Configured) WithOAuth(t OAuthTokens) *Configured {
	c.oauth = t
	return c
}

func (c *Configured) WithKeyring(k Keyring, owner func(name string) string) *Configured {
	c.keyring, c.owner = k, owner
	return c
}

// WithAsker lets the store ask you for a keyring secret that has no entry,
// and keep your answer in the keyring. It asks on the first read, and again
// only after Retry, so a dialog that you close does not come back on its own.
func (c *Configured) WithAsker(a Asker) *Configured {
	c.ask = a
	return c
}

func NewConfigured(backends map[string]Backend, run Runner, files FileReader) *Configured {
	return &Configured{backends: backends, run: run, files: files, now: time.Now, cache: map[string]cached{}, failed: map[string]failure{}}
}

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

func (c *Configured) Retry(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.failed, name)
}

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

func (c *Configured) fetch(ctx context.Context, name string, b Backend, firstTry bool) (Value, error) {
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
	if b.Keyring {
		return c.readKeyring(ctx, name, firstTry)
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	stdout, stderr, err := c.run.Output(ctx, Command{Secret: name, Argv: b.Command, Terminal: firstTry})
	if err != nil {
		return Value{}, &CommandError{Secret: name, Program: b.Command[0], Err: err, Stderr: lastLine(strings.TrimSpace(string(stderr)))}
	}
	return trimmed(name, stdout)
}

func (c *Configured) readKeyring(ctx context.Context, name string, firstTry bool) (Value, error) {
	if c.keyring == nil {
		return Value{}, fmt.Errorf("secret %q: the keyring is not available here", name)
	}
	owner := c.owner(name)
	v, err := c.keyring.Read(owner, name)
	switch {
	case errors.Is(err, ErrNotInKeyring) && firstTry && c.ask != nil:
		return c.askAndKeep(ctx, owner, name)
	case errors.Is(err, ErrNotInKeyring):
		return Value{}, fmt.Errorf("secret %q is not in the keyring: run %s", name, cli.Code(cli.Line("profiles", "login", owner, name)))
	case err != nil:
		return Value{}, fmt.Errorf("secret %q: %w", name, err)
	}
	return trimmed(name, v.b)
}

func (c *Configured) askAndKeep(ctx context.Context, owner, name string) (Value, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	answer, err := c.ask.Ask(ctx, owner, name)
	if err != nil {
		return Value{}, fmt.Errorf("secret %q: %w", name, err)
	}
	v, err := trimmed(name, answer.b)
	if err != nil {
		return Value{}, err
	}
	if err := c.keyring.Write(owner, name, v); err != nil {
		return Value{}, fmt.Errorf("secret %q: %w", name, err)
	}
	return v, nil
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
