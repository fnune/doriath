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
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/fnune/doriath/internal/profile"
)

const maxSignedBody = 64 << 20

var errUnsignedGoesAsItCame = errors.New("not signed")

type signOnTheWayOut func(*http.Request) error

func (s *Server) sigv4(ctx context.Context, c profile.Credential, r *http.Request) (signOnTheWayOut, error) {
	secret := c.Secret
	if query := r.URL.Query(); query.Get("X-Amz-Algorithm") != "" {
		key, _, _ := strings.Cut(query.Get("X-Amz-Credential"), "/")
		if c.KeyID != "" && key != c.KeyID {
			return nil, errUnsignedGoesAsItCame
		}
		return s.presigned(ctx, secret, r, query)
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
	chunked := payload == signedChunks || payload == signedChunksTrailer
	if strings.HasPrefix(payload, "STREAMING-AWS4-") && !chunked {
		return nil, fmt.Errorf("uploads signed as %s are not signed again", payload)
	}
	if payload == "" {
		hash, err := hashBody(r)
		if err != nil {
			return nil, err
		}
		payload = hash
	}
	creds, err := s.awsCredentials(ctx, secret)
	if err != nil {
		return nil, err
	}
	return func(out *http.Request) error {
		out.Header.Del("Authorization")
		out.Header.Del("X-Amz-Date")
		out.Header.Del("X-Amz-Security-Token")
		if err := v4.NewSigner().SignHTTP(out.Context(), creds, out, payload, service, region, time.Now()); err != nil {
			return err
		}
		if !chunked {
			return nil
		}
		chain, err := newChainSigner(creds, out, region, service)
		if err != nil {
			return err
		}
		out.Body = resignChunks(out.Body, chain, payload == signedChunksTrailer)
		return nil
	}, nil
}

var presignFields = []string{"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-SignedHeaders", "X-Amz-Signature", "X-Amz-Security-Token"}

func (s *Server) presigned(ctx context.Context, secret string, r *http.Request, query url.Values) (signOnTheWayOut, error) {
	if query.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" {
		return nil, fmt.Errorf("presigned with %q, not AWS4-HMAC-SHA256", query.Get("X-Amz-Algorithm"))
	}
	f := strings.Split(query.Get("X-Amz-Credential"), "/")
	if len(f) != 5 || f[2] == "" || f[3] == "" || f[4] != "aws4_request" {
		return nil, errors.New("the presigned URL has no valid X-Amz-Credential")
	}
	region, service := f[2], f[3]
	at, err := time.Parse("20060102T150405Z", query.Get("X-Amz-Date"))
	if err != nil {
		return nil, errors.New("the presigned URL has no valid X-Amz-Date")
	}
	payload := "UNSIGNED-PAYLOAD"
	if service != "s3" {
		if payload, err = hashBody(r); err != nil {
			return nil, err
		}
	}
	creds, err := s.awsCredentials(ctx, secret)
	if err != nil {
		return nil, err
	}
	for _, name := range presignFields {
		query.Del(name)
	}
	r.URL.RawQuery = query.Encode()
	return func(out *http.Request) error {
		out.Header.Del("Authorization")
		signed, _, err := v4.NewSigner().PresignHTTP(out.Context(), creds, out, payload, service, region, at)
		if err != nil {
			return err
		}
		u, err := url.Parse(signed)
		if err != nil {
			return err
		}
		out.URL.RawQuery = u.RawQuery
		return nil
	}, nil
}

func (s *Server) awsCredentials(ctx context.Context, secret string) (aws.Credentials, error) {
	v, err := s.secrets.Get(ctx, secret)
	if err != nil {
		return aws.Credentials{}, err
	}
	creds, err := parseAWSCredentials(v.Reveal())
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("secret %q: %w", secret, err)
	}
	return creds, nil
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
