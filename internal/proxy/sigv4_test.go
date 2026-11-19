package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const awsProfile = `
[secrets.aws]
command = ["creds"]

[[http]]
host = "sts.us-east-1.amazonaws.com"
credential = { secret = "aws", scheme = "sigv4", key_id = "AKIADORIATHPLACEHOLD" }
default = "allow"
`

var placeholder = aws.Credentials{AccessKeyID: "AKIADORIATHPLACEHOLD", SecretAccessKey: "placeholder"}

func signedAsInTheJail(t *testing.T, method, url, form string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(form))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sum := sha256.Sum256([]byte(form))
	if err := v4.NewSigner().SignHTTP(context.Background(), placeholder, req, hex.EncodeToString(sum[:]), "sts", "us-east-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	return req
}

func verifyAsAWSWould(t *testing.T, got *http.Request, payload []byte) {
	t.Helper()
	auth := got.Header.Get("Authorization")
	if !strings.Contains(auth, "Credential=AKIAREALKEY/") {
		t.Fatalf("signed with another key: %s", auth)
	}
	if got.Header.Get("X-Amz-Security-Token") != "real-session" {
		t.Errorf("session token = %q", got.Header.Get("X-Amz-Security-Token"))
	}
	_, afterSigned, ok := strings.Cut(auth, "SignedHeaders=")
	if !ok {
		t.Fatalf("no SignedHeaders: %s", auth)
	}
	signed, _, _ := strings.Cut(afterSigned, ",")
	at, err := time.Parse("20060102T150405Z", got.Header.Get("X-Amz-Date"))
	if err != nil {
		t.Fatal(err)
	}
	check, _ := http.NewRequest(got.Method, "https://"+got.Host+got.URL.RequestURI(), nil)
	check.ContentLength = got.ContentLength
	for _, name := range strings.Split(signed, ";") {
		if name != "host" {
			check.Header[http.CanonicalHeaderKey(name)] = got.Header.Values(name)
		}
	}
	check.Header.Del("X-Amz-Date")
	check.Header.Del("X-Amz-Security-Token")
	sum := sha256.Sum256(payload)
	real := aws.Credentials{AccessKeyID: "AKIAREALKEY", SecretAccessKey: "real-secret", SessionToken: "real-session"}
	if err := v4.NewSigner().SignHTTP(context.Background(), real, check, hex.EncodeToString(sum[:]), "sts", "us-east-1", at); err != nil {
		t.Fatal(err)
	}
	if check.Header.Get("Authorization") != auth {
		t.Fatalf("AWS would refuse the signature:\n got  %s\n want %s", auth, check.Header.Get("Authorization"))
	}
}

func TestARequestSignedWithPlaceholdersReachesAWSSignedWithTheRealKey(t *testing.T) {
	h := newHarnessWith(t, awsProfile)
	form := "Action=GetCallerIdentity&Version=2011-06-15"
	resp, err := h.client().Do(signedAsInTheJail(t, http.MethodPost, "https://sts.us-east-1.amazonaws.com/", form))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body(t, resp))
	}
	got, gotBody := h.upstream.last(t)
	if string(gotBody) != form {
		t.Fatalf("body = %q", gotBody)
	}
	verifyAsAWSWould(t, got, gotBody)
}

func TestRequestsThatCannotBeSignedAgainAreRefused(t *testing.T) {
	h := newHarnessWith(t, awsProfile)
	presigned, _ := http.NewRequest(http.MethodGet, "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIADORIATHPLACEHOLD%2Fbroken&X-Amz-Signature=abc", nil)
	presignedSigV2, _ := http.NewRequest(http.MethodGet, "https://sts.us-east-1.amazonaws.com/?X-Amz-Algorithm=AWS-HMAC-SHA1&X-Amz-Credential=AKIADORIATHPLACEHOLD%2F20261022%2Fus-east-1%2Fsts%2Faws4_request", nil)
	other, _ := http.NewRequest(http.MethodGet, "https://sts.us-east-1.amazonaws.com/", nil)
	other.Header.Set("Authorization", "Bearer something")
	for name, req := range map[string]*http.Request{"presigned with a broken credential": presigned, "presigned with another algorithm": presignedSigV2, "another scheme": other} {
		resp, err := h.client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if text := body(t, resp); resp.StatusCode != http.StatusBadRequest || !strings.Contains(text, "doriath: cannot sign") {
			t.Errorf("%s: status %d: %s", name, resp.StatusCode, text)
		}
	}
}

func TestAnUploadWithUnsignedChunksIsSignedAgain(t *testing.T) {
	h := newHarnessWith(t, awsProfile)
	req := signedAsInTheJail(t, http.MethodPut, "https://sts.us-east-1.amazonaws.com/upload", "")
	req.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if text := body(t, resp); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, text)
	}
	if got, _ := h.upstream.last(t); !strings.Contains(got.Header.Get("Authorization"), "Credential=AKIAREALKEY/") {
		t.Errorf("Authorization = %q", got.Header.Get("Authorization"))
	}
}

func TestAHugeChunkSizeFailsTheUploadAndLeavesTheProxyRunning(t *testing.T) {
	h := newHarnessWith(t, awsProfile)
	huge := "7fffffffffffffff;chunk-signature=" + strings.Repeat("a", 64) + "\r\n"
	req := signedAsInTheJail(t, http.MethodPut, "https://sts.us-east-1.amazonaws.com/x", huge)
	req.Header.Set("X-Amz-Content-Sha256", signedChunks)
	if resp, err := h.client().Do(req); err == nil {
		if body(t, resp); resp.StatusCode < 400 {
			t.Fatalf("status %d for an upload with an impossible chunk", resp.StatusCode)
		}
	}
	resp, err := h.client().Get("https://sts.us-east-1.amazonaws.com/after")
	if err != nil {
		t.Fatal(err)
	}
	body(t, resp)
}

func TestAPresignedURLIsSignedAgainInItsQuery(t *testing.T) {
	h := newHarnessWith(t, awsProfile)
	req, _ := http.NewRequest(http.MethodGet, "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Expires=900", nil)
	at := time.Now().Add(-time.Minute).UTC()
	signed, _, err := v4.NewSigner().PresignHTTP(context.Background(), placeholder, req, emptyHash, "sts", "us-east-1", at)
	if err != nil {
		t.Fatal(err)
	}
	get, _ := http.NewRequest(http.MethodGet, signed, nil)
	resp, err := h.client().Do(get)
	if err != nil {
		t.Fatal(err)
	}
	if text := body(t, resp); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, text)
	}
	got, _ := h.upstream.last(t)
	q := got.URL.Query()
	if !strings.HasPrefix(q.Get("X-Amz-Credential"), "AKIAREALKEY/") || q.Get("X-Amz-Security-Token") != "real-session" || q.Get("X-Amz-Expires") != "900" || q.Get("Action") != "GetCallerIdentity" {
		t.Errorf("query = %v", q)
	}
}

func TestAPresignedURLIsSignedForNowAndAnHourAtMost(t *testing.T) {
	h := newHarnessWith(t, awsProfile)
	req, _ := http.NewRequest(http.MethodGet, "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Expires=604800", nil)
	signed, _, err := v4.NewSigner().PresignHTTP(context.Background(), placeholder, req, emptyHash, "sts", "us-east-1", time.Now().Add(6*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	get, _ := http.NewRequest(http.MethodGet, signed, nil)
	resp, err := h.client().Do(get)
	if err != nil {
		t.Fatal(err)
	}
	if text := body(t, resp); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, text)
	}
	got, _ := h.upstream.last(t)
	q := got.URL.Query()
	at, err := time.Parse("20060102T150405Z", q.Get("X-Amz-Date"))
	if err != nil || time.Since(at).Abs() > time.Minute {
		t.Errorf("signed for %s, not for now", q.Get("X-Amz-Date"))
	}
	if q.Get("X-Amz-Expires") != "3600" {
		t.Errorf("expires = %q", q.Get("X-Amz-Expires"))
	}
}

func TestAURLThatAWSPresignedPassesAsItIs(t *testing.T) {
	h := newHarnessWith(t, awsProfile)
	theirs := "https://sts.us-east-1.amazonaws.com/layer?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIAAWSOWNED%2F20261022%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20261022T000000Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host&X-Amz-Signature=abc"
	resp, err := h.client().Get(theirs)
	if err != nil {
		t.Fatal(err)
	}
	if text := body(t, resp); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, text)
	}
	if got, _ := h.upstream.last(t); got.URL.Query().Get("X-Amz-Signature") != "abc" {
		t.Errorf("AWS's own presigned URL was changed: %s", got.URL.RawQuery)
	}
}

const emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestSigV4Scope(t *testing.T) {
	region, service, ok := sigv4Scope("AWS4-HMAC-SHA256 Credential=AKIA/20261022/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc")
	if !ok || region != "eu-west-1" || service != "s3" {
		t.Errorf("scope = %q %q %v", region, service, ok)
	}
	if _, _, ok := sigv4Scope("AWS4-HMAC-SHA256 Credential=AKIA/20261022/aws4_request"); ok {
		t.Error("a short credential scope must not parse")
	}
}

func TestAnApprovalNamesTheOperationThatThePathDoesNot(t *testing.T) {
	h := newHarnessWith(t, strings.Replace(awsProfile, `default = "allow"`, `operation = { header = "X-Amz-Target", form = "Action" }`, 1))
	for _, action := range []string{"DeleteStack", "DescribeStacks"} {
		resp, err := h.client().Do(signedAsInTheJail(t, http.MethodPost, "https://sts.us-east-1.amazonaws.com/", "Action="+action))
		if err != nil {
			t.Fatal(err)
		}
		_ = body(t, resp)
	}
	reqs := h.approver.requests
	if len(reqs) != 2 {
		t.Fatalf("approvals = %d", len(reqs))
	}
	if !strings.Contains(reqs[0].Summary, "Action=DeleteStack") || !strings.HasSuffix(reqs[0].Scope, "operation Action=DeleteStack") {
		t.Errorf("approval = %q, scope %q", reqs[0].Summary, reqs[0].Scope)
	}
	if reqs[0].Scope == reqs[1].Scope {
		t.Errorf("an allow for the session of one operation covers another: %q", reqs[0].Scope)
	}
}
