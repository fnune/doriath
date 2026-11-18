package vcstools

type Tool interface {
	Name() string
	HostSigns() string
	Jail(j Jail) Config
}

type Jail struct {
	// SigningKey is the jail's path to the profile's public signing key,
	// or "" when commits stay unsigned.
	SigningKey string
	RewriteSSH []SSHRewrite
	// SSHCommand is what git runs in place of ssh, which has no route out
	// of the jail.
	SSHCommand string
	Path       func(name string) string
	// JJGit is the git that jj runs, a doriath front that keeps the paths
	// of git worktrees absolute, or "" for plain git.
	JJGit string
}

type SSHRewrite struct {
	Host     string
	SSHHosts []string
	User     string
	Port     int
}

type Config struct {
	Files map[string][]byte
	Env   map[string]string
}
