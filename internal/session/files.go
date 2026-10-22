package session

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

var caBundleCandidates = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/ssl/cert.pem",
}

// CABundle is the system's trusted roots plus the session CA, for tools that
// read one bundle file.
func CABundle(getenv func(string) string, read func(string) ([]byte, error), sessionCA []byte) ([]byte, error) {
	candidates := []string{getenv("SSL_CERT_FILE"), getenv("NIX_SSL_CERT_FILE")}
	candidates = append(candidates, caBundleCandidates...)
	for _, c := range candidates {
		if c == "" {
			continue
		}
		data, err := read(c)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read CA bundle %s: %w", c, err)
		}
		out := append(bytes.TrimRight(data, "\n"), '\n')
		return append(out, sessionCA...), nil
	}
	return nil, errors.New("no system CA bundle found: set SSL_CERT_FILE")
}

// JavaTrustStorePassword opens the Java trust store. It protects nothing,
// since the store holds only public certificates, but Java wants one.
const JavaTrustStorePassword = "changeit"

// JavaTrustStore turns a PEM bundle into a PKCS12 trust store, because Java,
// and so Bazel, Gradle and Maven, reads neither SSL_CERT_FILE nor PEM files.
func JavaTrustStore(bundle []byte) ([]byte, error) {
	var certs []*x509.Certificate
	for rest := bundle; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("the CA bundle holds no certificate")
	}
	return pkcs12.Modern.EncodeTrustStore(certs, JavaTrustStorePassword)
}

// BazelRC sets the trust store as JVM startup flags, because the Bazel client
// drops JAVA_TOOL_OPTIONS before it starts its server.
func BazelRC(trustStore string) []byte {
	var b strings.Builder
	b.WriteString("# Written by doriath for this session.\n")
	for _, opt := range []string{
		"-Djavax.net.ssl.trustStore=" + trustStore,
		"-Djavax.net.ssl.trustStoreType=PKCS12",
		"-Djavax.net.ssl.trustStorePassword=" + JavaTrustStorePassword,
	} {
		b.WriteString("startup --host_jvm_args=" + opt + "\n")
	}
	return []byte(b.String())
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`)
	return `"` + r.Replace(s) + `"`
}
