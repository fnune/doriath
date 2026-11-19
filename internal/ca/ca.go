package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	rootLifetime = 30 * 24 * time.Hour
	leafLifetime = 7 * 24 * time.Hour
	maxLeaves    = 1024
)

// Authority lives for one session and only in memory. Its name constraints
// limit it to the intercepted hosts, so even a leaked key cannot vouch for
// any other host.
type Authority struct {
	key       *ecdsa.PrivateKey
	cert      *x509.Certificate
	certPEM   []byte
	permitted []string
	now       func() time.Time

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

func New(hosts []string, now func() time.Time) (*Authority, error) {
	if len(hosts) == 0 {
		return nil, errors.New("a session authority needs at least one host")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	var permitted []string
	for _, h := range hosts {
		h = withoutPort(h)
		if d, ok := strings.CutPrefix(h, "*."); ok {
			permitted = append(permitted, "."+d)
		} else {
			permitted = append(permitted, h)
		}
	}
	start := now().Add(-time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber:                serial(),
		Subject:                     pkix.Name{CommonName: "doriath session CA", Organization: []string{"doriath"}},
		NotBefore:                   start,
		NotAfter:                    start.Add(rootLifetime),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         permitted,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	return &Authority{
		key:       key,
		cert:      cert,
		certPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		permitted: permitted,
		now:       now,
		leaves:    map[string]*tls.Certificate{},
	}, nil
}

func withoutPort(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		return h[1 : len(h)-1]
	}
	return h
}

func (a *Authority) CertPEM() []byte { return append([]byte(nil), a.certPEM...) }

func (a *Authority) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.cert)
	return pool
}

func (a *Authority) Certificate(host string) (*tls.Certificate, error) {
	host = strings.ToLower(host)
	if net.ParseIP(host) != nil {
		return nil, fmt.Errorf("refusing to issue a certificate for IP address %s", host)
	}
	if !a.covers(host) {
		return nil, fmt.Errorf("host %s is outside this session's intercepted hosts", host)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if leaf, ok := a.leaves[host]; ok && a.now().Before(leaf.Leaf.NotAfter.Add(-time.Hour)) {
		return leaf, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key for %s: %w", host, err)
	}
	start := a.now().Add(-time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    start,
		NotAfter:     start.Add(leafLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, fmt.Errorf("create certificate for %s: %w", host, err)
	}
	leafCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate for %s: %w", host, err)
	}
	leaf := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leafCert}
	if len(a.leaves) >= maxLeaves {
		for old := range a.leaves {
			delete(a.leaves, old)
			break
		}
	}
	a.leaves[host] = leaf
	return leaf, nil
}

func (a *Authority) covers(host string) bool {
	for _, p := range a.permitted {
		if strings.HasPrefix(p, ".") {
			if strings.HasSuffix(host, p) {
				return true
			}
		} else if host == p {
			return true
		}
	}
	return false
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return n
}
