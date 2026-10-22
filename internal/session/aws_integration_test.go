//go:build integration

package session_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/secret"
)

func TestTheAWSCLISignsWithPlaceholdersAndAWSGetsTheRealKey(t *testing.T) {
	aws, err := filepath.EvalSymlinks(filepath.Join(os.Getenv("HOME"), ".nix-profile", "bin", "aws"))
	if err != nil {
		t.Skip("no AWS CLI from nix")
	}
	e := newEnv(t)
	creds := filepath.Join(t.TempDir(), "aws.json")
	if err := os.WriteFile(creds, []byte(`{"Version":1,"AccessKeyId":"AKIAREALKEY","SecretAccessKey":"real-secret","SessionToken":"real-session"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	e.secrets["aws"] = secret.Backend{File: creds}
	p := e.profile(`
[env]
set = { AWS_ACCESS_KEY_ID = "AKIADORIATHPLACEHOLD", AWS_SECRET_ACCESS_KEY = "doriath-placeholder", AWS_REGION = "us-east-1" }

[[http]]
host = "sts.us-east-1.amazonaws.com"
credential = { secret = "aws", scheme = "sigv4" }
default = "allow"
`)
	code, out := e.run(p, aws+` sts get-caller-identity --endpoint-url https://sts.us-east-1.amazonaws.com >/dev/null 2>&1
key="real"; key="$key-secret"; grep -rqs "$key" /run/doriath "$HOME" /tmp && echo "FAIL the secret key is in the jail"
echo done
`, nil)
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "done") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	r := e.upstream.find("/")
	if r == nil {
		t.Fatalf("STS never saw the request:\n%s", out)
	}
	if auth := r.Header.Get("Authorization"); !strings.Contains(auth, "Credential=AKIAREALKEY/") || !strings.Contains(auth, "/us-east-1/sts/aws4_request") {
		t.Errorf("Authorization = %q", auth)
	}
	if r.Header.Get("X-Amz-Security-Token") != "real-session" {
		t.Errorf("session token = %q", r.Header.Get("X-Amz-Security-Token"))
	}
}
