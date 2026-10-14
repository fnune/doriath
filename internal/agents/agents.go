// Package agents adapts coding agents to girdle where profile data cannot:
// an agent's permission prompts reach girdle's approvals, and its
// transcripts come back to your own configuration. Everything else about
// an agent, such as its state, config, hosts and credentials, is an
// ordinary module.
package agents

import "github.com/fnune/girdle/internal/profile"

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
}

type Adapter interface {
	Matches(argv []string) bool
	// Start runs before the jail starts and returns the command to run
	// and the environment it adds.
	Start(s Session, argv []string) ([]string, map[string]string, error)
	// End runs after the session ends.
	End(s Session) error
}
