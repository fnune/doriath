package session

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// gitDenied are git settings from the desktop that must not reach the jail:
// credential helpers, URL rewrites to SSH, includes of files the jail cannot
// see, and settings that name programs or keys outside the jail.
var gitDenied = []string{
	"credential.", "url.", "include.", "includeif.", "http.", "sendemail.", "remote.", "branch.",
	"core.sshcommand", "core.askpass", "core.hookspath", "core.fsmonitor", "core.editor",
	"gpg.program", "gpg.ssh.program", "gpg.ssh.allowedsignersfile", "user.signingkey",
}

func gitAllowed(key string) bool {
	k := strings.ToLower(key)
	for _, d := range gitDenied {
		if strings.HasSuffix(d, ".") && strings.HasPrefix(k, d) || k == d {
			return false
		}
	}
	return true
}

type gitEntry struct{ key, value string }

// parseGitList reads the output of git config --list -z.
func parseGitList(data []byte) []gitEntry {
	var out []gitEntry
	for _, rec := range bytes.Split(data, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		key, value, _ := strings.Cut(string(rec), "\n")
		out = append(out, gitEntry{key: key, value: value})
	}
	return out
}

type GitOptions struct {
	SigningKey string
	RewriteSSH []string
	Desktop    []byte
}

// GitConfig builds the jail's global git config from the desktop's, keeping
// identity and preferences and replacing everything that points outside.
func GitConfig(o GitOptions) []byte {
	var entries []gitEntry
	for _, e := range parseGitList(o.Desktop) {
		if gitAllowed(e.key) {
			entries = append(entries, e)
		}
	}
	set := func(key, value string) {
		entries = append(entries, gitEntry{key: key, value: value})
	}
	if o.SigningKey != "" {
		set("gpg.format", "ssh")
		set("user.signingkey", o.SigningKey)
		set("commit.gpgsign", "true")
	} else {
		set("commit.gpgsign", "false")
		set("tag.gpgsign", "false")
	}
	set("credential.helper", "")
	for _, host := range o.RewriteSSH {
		set(fmt.Sprintf("url.https://%s/.insteadof", host), fmt.Sprintf("git@%s:", host))
		set(fmt.Sprintf("url.https://%s/.insteadof", host), fmt.Sprintf("ssh://git@%s/", host))
	}
	return renderGit(entries)
}

func renderGit(entries []gitEntry) []byte {
	type section struct {
		header string
		lines  []string
	}
	var order []string
	sections := map[string]*section{}
	for _, e := range entries {
		first := strings.Index(e.key, ".")
		last := strings.LastIndex(e.key, ".")
		if first < 0 {
			continue
		}
		name := e.key[last+1:]
		header := fmt.Sprintf("[%s]", e.key[:first])
		if first != last {
			sub := e.key[first+1 : last]
			header = fmt.Sprintf("[%s %s]", e.key[:first], quote(sub))
		}
		s, ok := sections[header]
		if !ok {
			s = &section{header: header}
			sections[header] = s
			order = append(order, header)
		}
		s.lines = append(s.lines, fmt.Sprintf("\t%s = %s", name, quote(e.value)))
	}
	var b bytes.Buffer
	for _, h := range order {
		b.WriteString(h + "\n")
		for _, l := range sections[h].lines {
			b.WriteString(l + "\n")
		}
	}
	return b.Bytes()
}

func quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`)
	return `"` + r.Replace(s) + `"`
}

// JJConfig overrides the desktop's jj signing settings, which point at a key
// the jail does not have.
func JJConfig(signingKey string) []byte {
	if signingKey == "" {
		return []byte("[signing]\nbehavior = \"keep\"\n")
	}
	return []byte(fmt.Sprintf("[signing]\nbehavior = \"own\"\nbackend = \"ssh\"\nkey = %s\n", quote(signingKey)))
}

// JJConfigPath lists the desktop's jj config files first and girdle's
// override last, because jj merges them in that order.
func JJConfigPath(home string, kind func(string) string, override string) string {
	var parts []string
	dir := filepath.Join(home, ".config", "jj")
	for _, p := range []string{filepath.Join(dir, "config.toml"), filepath.Join(dir, "conf.d")} {
		if kind(p) != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(append(parts, override), ":")
}

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
			// System bundles carry the odd certificate Go cannot parse;
			// leaving it out only means Java does not trust that root.
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
	b.WriteString("# Written by girdle for this session.\n")
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
