//go:build integration

package session_test

import (
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fnune/doriath/internal/approval"
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

func TestAWSAcceptsWhatTheProxySignsAgain(t *testing.T) {
	floci := os.Getenv("FLOCI_URL")
	if floci == "" {
		t.Skip("FLOCI_URL is not set: run just test-floci")
	}
	aws, err := filepath.EvalSymlinks(filepath.Join(os.Getenv("HOME"), ".nix-profile", "bin", "aws"))
	if err != nil {
		t.Skip("no AWS CLI from nix")
	}
	target, err := url.Parse(floci)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	e.upstream.answerWith = &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		pr.Out.Host = pr.In.Host
	}}
	creds := filepath.Join(t.TempDir(), "aws.json")
	if err := os.WriteFile(creds, []byte(`{"Version":1,"AccessKeyId":"test","SecretAccessKey":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	e.secrets["aws"] = secret.Backend{File: creds}
	e.modules = []string{"aws"}
	p := e.profile("\n[env]\nset = { AWS_REGION = \"us-east-1\", AWS_PAGER = \"\" }\n")
	bucket := "doriath-test"
	code, out := e.run(p, `
set -u
aws=`+aws+`
run() { echo "== $*"; "$aws" "$@" || echo "FAIL $*"; }
run sts get-caller-identity
run s3api create-bucket --bucket `+bucket+`
head -c 300000 /dev/urandom > big.bin
run s3 cp big.bin s3://`+bucket+`/big.bin
run s3 ls s3://`+bucket+`/
url=$("$aws" s3 presign s3://`+bucket+`/big.bin)
case "$url" in *AKIADORIATHPLACEHOLD*) ;; *) echo "FAIL the presigned URL is not signed with the placeholder: $url" ;; esac
curl -fsS -o fetched.bin "$url" && cmp -s big.bin fetched.bin || echo "FAIL a presigned URL through the proxy"
zeros=0000000000000000000000000000000000000000000000000000000000000000
now=$(date -u +%Y%m%dT%H%M%SZ)
{ printf '5;chunk-signature=%s\r\nhello\r\n0;chunk-signature=%s\r\n\r\n' $zeros $zeros; } > chunked.body
curl -fsS -X PUT --data-binary @chunked.body \
	-H "Authorization: AWS4-HMAC-SHA256 Credential=AKIADORIATHPLACEHOLD/${now%%T*}/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=$zeros" \
	-H "X-Amz-Date: $now" -H "X-Amz-Content-Sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD" \
	-H "Content-Encoding: aws-chunked" -H "X-Amz-Decoded-Content-Length: 5" -H "Content-Type: text/plain" \
	https://s3.us-east-1.amazonaws.com/`+bucket+`/chunked.txt >/dev/null || echo "FAIL an upload with signed chunks"
[ "$("$aws" s3 cp s3://`+bucket+`/chunked.txt -)" = hello ] || echo "FAIL the chunked upload stored something else"
run dynamodb list-tables
run cloudformation describe-stacks
"$aws" sts assume-role --role-arn arn:aws:iam::000000000000:role/x --role-session-name s >/dev/null 2>&1 && echo "FAIL assume-role went through"
echo done
`, func() {
		for range 3 {
			e.decideNext(approval.Decision{Verdict: approval.VerdictAllow, Lasting: approval.LastingOnce, By: "test"})
		}
	})
	if code != 0 || strings.Contains(out, "FAIL") || !strings.Contains(out, "done") || strings.Contains(out, "SignatureDoesNotMatch") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}
