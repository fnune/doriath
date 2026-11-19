package profile

import "testing"

func TestPassRiskNamesCredentialsSocketsAndLoaders(t *testing.T) {
	for _, name := range []string{"GITHUB_TOKEN", "OPENAI_API_KEY", "DB_PASSWORD", "CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS", "AWS_PROFILE", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "SSH_AUTH_SOCK", "GPG_AGENT_INFO", "DATABASE_URL", "DB_PASS", "SENTRY_DSN", "DISPLAY", "XAUTHORITY"} {
		if PassRisk(name) == "" {
			t.Errorf("%s has no reason", name)
		}
	}
	for _, name := range append(defaults.Env.Pass, "DEBUG", "GOFLAGS", "GOPRIVATE", "GIT_AUTHOR_NAME", "PASSTHROUGH", "COMPASS") {
		if reason := PassRisk(name); reason != "" {
			t.Errorf("%s is marked: %s", name, reason)
		}
	}
}
