package proxy

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const (
	signedChunks        = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	signedChunksTrailer = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
)

type chainSigner struct {
	key      []byte
	date     string
	scope    string
	previous string
}

const maxSignedChunk = 16 << 20

func newChainSigner(creds aws.Credentials, out *http.Request, region, service string) (*chainSigner, error) {
	amzDate := out.Header.Get("X-Amz-Date")
	_, seed, ok := strings.Cut(out.Header.Get("Authorization"), "Signature=")
	if len(amzDate) < 8 || !ok {
		return nil, errors.New("the request has no signature to chain the chunks from")
	}
	return chainFrom(creds.SecretAccessKey, amzDate, region, service, seed), nil
}

func chainFrom(secretKey, amzDate, region, service, seed string) *chainSigner {
	day := amzDate[:8]
	key := hmacSHA256([]byte("AWS4"+secretKey), day)
	for _, part := range []string{region, service, "aws4_request"} {
		key = hmacSHA256(key, part)
	}
	return &chainSigner{key: key, date: amzDate, scope: day + "/" + region + "/" + service + "/aws4_request", previous: seed}
}

func (c *chainSigner) chunk(data []byte) string {
	return c.next("AWS4-HMAC-SHA256-PAYLOAD", hexSHA256(nil), hexSHA256(data))
}

func (c *chainSigner) trailer(canonical []byte) string {
	return c.next("AWS4-HMAC-SHA256-TRAILER", hexSHA256(canonical))
}

func (c *chainSigner) next(algorithm string, hashes ...string) string {
	toSign := strings.Join(append([]string{algorithm, c.date, c.scope, c.previous}, hashes...), "\n")
	c.previous = hex.EncodeToString(hmacSHA256(c.key, toSign))
	return c.previous
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func hexSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func resignChunks(body io.ReadCloser, c *chainSigner, trailer bool) io.ReadCloser {
	r, w := io.Pipe()
	go func() {
		defer body.Close()
		defer func() {
			if v := recover(); v != nil {
				w.CloseWithError(fmt.Errorf("resign chunks: %v", v))
			}
		}()
		w.CloseWithError(copyChunks(w, bufio.NewReader(body), c, trailer))
	}()
	return r
}

func copyChunks(w io.Writer, in *bufio.Reader, c *chainSigner, trailer bool) error {
	for {
		header, err := readLine(in)
		if err != nil {
			return err
		}
		sizeHex, ext, ok := strings.Cut(header, ";")
		old, isSig := strings.CutPrefix(ext, "chunk-signature=")
		if !ok || !isSig || len(old) != 64 {
			return fmt.Errorf("chunk header %q has no chunk signature", header)
		}
		size, err := strconv.ParseInt(sizeHex, 16, 64)
		if err != nil || size < 0 {
			return fmt.Errorf("chunk header %q has no size", header)
		}
		if size > maxSignedChunk {
			return fmt.Errorf("chunk of %d bytes is over the limit of %d", size, maxSignedChunk)
		}
		var buf bytes.Buffer
		if _, err := io.CopyN(&buf, in, size); err != nil {
			if errors.Is(err, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		data := buf.Bytes()
		if size > 0 {
			if end, err := readLine(in); err != nil || end != "" {
				return errors.New("a chunk does not end with CRLF")
			}
		}
		if _, err := fmt.Fprintf(w, "%s;chunk-signature=%s\r\n", sizeHex, c.chunk(data)); err != nil {
			return err
		}
		if size > 0 {
			if _, err := w.Write(append(data, '\r', '\n')); err != nil {
				return err
			}
			continue
		}
		if !trailer {
			_, err := io.Copy(w, in)
			return err
		}
		return copyTrailer(w, in, c)
	}
}

func copyTrailer(w io.Writer, in *bufio.Reader, c *chainSigner) error {
	var canonical []byte
	for {
		line, err := readLine(in)
		if err != nil {
			return err
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return fmt.Errorf("trailer line %q is not a header", line)
		}
		if strings.EqualFold(name, "x-amz-trailer-signature") {
			if _, err := fmt.Fprintf(w, "%s:%s\r\n", name, c.trailer(canonical)); err != nil {
				return err
			}
			_, err := io.Copy(w, in)
			return err
		}
		canonical = append(canonical, strings.ToLower(name)+":"+strings.TrimSpace(value)+"\n"...)
		if _, err := fmt.Fprintf(w, "%s\r\n", line); err != nil {
			return err
		}
	}
}

func readLine(in *bufio.Reader) (string, error) {
	line, err := in.ReadString('\n')
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(line, "\r\n") {
		return "", errors.New("a line does not end with CRLF")
	}
	return strings.TrimSuffix(line, "\r\n"), nil
}
