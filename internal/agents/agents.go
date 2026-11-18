package agents

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/fnune/doriath/internal/profile"
)

type Session struct {
	Profile *profile.Profile
	Home    string
	Cwd     string
	// HostPath returns where a path in the jail lives on the host when a
	// profile cache backs it, or "" when nothing outside the jail keeps it.
	HostPath func(jailPath string) string
	// WriteFile puts a file into the session's directory, which the jail
	// sees read-only, and returns its path in the jail.
	WriteFile func(name string, data []byte) (string, error)
	// Place puts a file at a path in the jail, read-only, for config the
	// agent must not change during the session.
	Place        func(jailPath string, data []byte) error
	Touch        func(jailPath string) error
	Later        func(after time.Duration, work func() error)
	MCPConfig    string
	Instructions string
	Titled       bool
	ToolWait     time.Duration
}

type Adapter interface {
	// Name is the adapter's agent, and the name of the module that gives
	// the agent its config, state and hosts. A profile gets the adapter
	// only when it lists that module.
	Name() string
	Command() string
	Matches(argv []string) bool
	Seeds(s Session) []Seed
	Start(s Session, argv []string) ([]string, map[string]string, error)
	End(s Session) error
}

type Starter interface {
	Started(s Session) error
}

type mcpServer struct {
	Type    string            `json:"type,omitempty"`
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	URL     string            `json:"url,omitempty"`
}

func MCPConfig(servers []profile.MCPServer) ([]byte, error) {
	out := map[string]map[string]mcpServer{"mcpServers": {}}
	for _, s := range servers {
		if s.URL != "" {
			out["mcpServers"][s.Name] = mcpServer{Type: "http", URL: s.URL}
			continue
		}
		out["mcpServers"][s.Name] = mcpServer{Command: s.Command[0], Args: s.Command[1:], Env: s.Env}
	}
	data, err := json.MarshalIndent(out, "", "  ")
	return append(data, '\n'), err
}

// Seed copies the named top-level keys of a JSON file of yours into a
// profile's own state, once, when that file does not exist yet. Only the
// keys listed travel: settings such as onboarding done, never accounts,
// servers or project history.
type Seed struct {
	Source string
	Dest   string
	Keys   []string
}

// Plant writes each seed whose destination is missing. A missing or
// unreadable source plants nothing: the agent then starts fresh.
func Plant(seeds []Seed) error {
	var errs []error
	for _, seed := range seeds {
		if _, err := os.Lstat(seed.Dest); !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		data, err := os.ReadFile(seed.Source)
		if err != nil {
			continue
		}
		var doc map[string]json.RawMessage
		if json.Unmarshal(data, &doc) != nil {
			continue
		}
		kept := map[string]json.RawMessage{}
		for k, v := range doc {
			if slices.Contains(seed.Keys, k) {
				kept[k] = v
			}
		}
		out, err := json.MarshalIndent(kept, "", "  ")
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(seed.Dest), 0o700); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := os.WriteFile(seed.Dest, append(out, '\n'), 0o600); err != nil {
			errs = append(errs, fmt.Errorf("seed %s: %w", seed.Dest, err))
		}
	}
	return errors.Join(errs...)
}
