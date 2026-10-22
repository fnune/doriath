package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const maxSignedBody = 64 << 20

var errUnsignedGoesAsItCame = errors.New("not signed")

type signOnTheWayOut func(*http.Request) error

func (s *Server) sigv4(ctx context.Context, secret string, r *http.Request) (signOnTheWayOut, error) {
	if r.URL.Query().Get("X-Amz-Algorithm") != "" {
		return nil, errors.New("presigned requests are not signed again; send the request with an Authorization header")
	}
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, errUnsignedGoesAsItCame
	}
	region, service, ok := sigv4Scope(auth)
	if !ok {
		return nil, errors.New("the Authorization header is not an AWS4-HMAC-SHA256 signature")
	}
	payload := r.Header.Get("X-Amz-Content-Sha256")
	if strings.HasPrefix(payload, "STREAMING-AWS4-") {
		return nil, errors.New("uploads that sign each chunk are not signed again; send the upload without chunk signatures")
	}
	if payload == "" {
		hash, err := hashBody(r)
		if err != nil {
			return nil, err
		}
		payload = hash
	}
	v, err := s.secrets.Get(ctx, secret)
	if err != nil {
		return nil, err
	}
	creds, err := parseAWSCredentials(v.Reveal())
	if err != nil {
		return nil, fmt.Errorf("secret %q: %w", secret, err)
	}
	return func(out *http.Request) error {
		out.Header.Del("Authorization")
		out.Header.Del("X-Amz-Date")
		out.Header.Del("X-Amz-Security-Token")
		return v4.NewSigner().SignHTTP(out.Context(), creds, out, payload, service, region, time.Now())
	}, nil
}

func sigv4Scope(auth string) (region, service string, ok bool) {
	rest, ok := strings.CutPrefix(auth, "AWS4-HMAC-SHA256 ")
	if !ok {
		return "", "", false
	}
	for part := range strings.SplitSeq(rest, ",") {
		value, ok := strings.CutPrefix(strings.TrimSpace(part), "Credential=")
		if !ok {
			continue
		}
		f := strings.Split(value, "/")
		if len(f) == 5 && f[2] != "" && f[3] != "" && f[4] == "aws4_request" {
			return f[2], f[3], true
		}
	}
	return "", "", false
}

func hashBody(r *http.Request) (string, error) {
	if r.Body == nil || r.Body == http.NoBody {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:]), nil
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxSignedBody+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxSignedBody {
		return "", fmt.Errorf("the body is over %d MB, which doriath does not hash to sign; send X-Amz-Content-Sha256", maxSignedBody>>20)
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func parseAWSCredentials(data []byte) (aws.Credentials, error) {
	var c struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		SessionToken    string `json:"SessionToken"`
	}
	if err := json.Unmarshal(data, &c); err != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return aws.Credentials{}, errors.New("want the JSON that credential_process prints, with AccessKeyId and SecretAccessKey")
	}
	return aws.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken}, nil
}

type signingTransport struct {
	base http.RoundTripper
	sign signOnTheWayOut
}

func (t signingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := t.sign(r); err != nil {
		return nil, fmt.Errorf("sign the request: %w", err)
	}
	return t.base.RoundTrip(r)
}
