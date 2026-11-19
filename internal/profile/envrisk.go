package profile

import "strings"

// PassRisk says why passing the host variable name into the jail can give
// the agent more than a setting: a credential, a socket to a key agent on
// the host, or a change to the code that programs load. It is empty for
// other names. doriath passes such names, and the allow prompt shows the
// reason.
func PassRisk(name string) string {
	upper := strings.ToUpper(name)
	switch upper {
	case "SSH_AUTH_SOCK", "GPG_AGENT_INFO", "DBUS_SESSION_BUS_ADDRESS", "DOCKER_HOST", "DISPLAY":
		return "connects to a service on your machine"
	case "SSH_ASKPASS", "GIT_ASKPASS", "SUDO_ASKPASS", "GIT_SSH", "GIT_SSH_COMMAND":
		return "changes how programs authenticate"
	case "BASH_ENV", "ENV", "NODE_OPTIONS", "PYTHONPATH", "PYTHONSTARTUP", "PERL5LIB", "PERL5OPT", "RUBYOPT", "RUBYLIB":
		return "changes the code that programs load"
	case "KUBECONFIG", "DOCKER_CONFIG", "NETRC", "XAUTHORITY", "DATABASE_URL":
		return "can hold a credential"
	}
	for _, prefix := range []string{"LD_", "DYLD_"} {
		if strings.HasPrefix(upper, prefix) {
			return "changes the code that programs load"
		}
	}
	for _, prefix := range []string{"AWS_", "AZURE_", "GOOGLE_", "GCLOUD_", "CLOUDSDK_"} {
		if strings.HasPrefix(upper, prefix) {
			return "can hold a cloud credential"
		}
	}
	for _, part := range []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "APIKEY", "API_KEY", "PRIVATE_KEY"} {
		if strings.Contains(upper, part) {
			return "can hold a credential"
		}
	}
	if strings.HasSuffix(upper, "_KEY") || strings.HasSuffix(upper, "_PAT") || strings.HasSuffix(upper, "_PASS") || strings.HasSuffix(upper, "_DSN") {
		return "can hold a credential"
	}
	return ""
}
