// Package vcstools is what a session needs from each version control tool:
// whether your own config makes it sign commits, and its config inside the
// jail. Each tool has a package of its own, so the session names none.
package vcstools

type Tool interface {
	Name() string
	// HostSigns names the setting of your own config that makes the tool
	// sign commits, or returns "" when the tool signs nothing.
	HostSigns() string
	// Jail returns the tool's config for a session.
	Jail(j Jail) Config
}

type Jail struct {
	// SigningKey is the jail's path to the profile's public signing key,
	// or "" when commits stay unsigned.
	SigningKey string
	// RewriteSSH are remotes that the jail reaches over HTTPS in place of
	// SSH.
	RewriteSSH []SSHRewrite
	// SSHCommand is what git runs in place of ssh, which has no route out
	// of the jail.
	SSHCommand string
	// Path is the jail's path to a file of the session's directory.
	Path func(name string) string
}

type SSHRewrite struct {
	// Host is the HTTPS host, which serves the remotes of SSHHosts too.
	Host     string
	SSHHosts []string
	User     string
	Port     int
}

// Config is what a tool reads in the jail: files that the session writes
// into its directory, by name, and the environment that points at them.
type Config struct {
	Files map[string][]byte
	Env   map[string]string
}
