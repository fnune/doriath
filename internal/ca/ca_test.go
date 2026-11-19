package ca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"
)

func TestLeafVerifiesAgainstRoot(t *testing.T) {
	a, err := New([]string{"api.github.com", "*.githubusercontent.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"api.github.com", "objects.githubusercontent.com"} {
		leaf, err := a.Certificate(host)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: a.Pool()}); err != nil {
			t.Errorf("%s: %v", host, err)
		}
		again, _ := a.Certificate(host)
		if again != leaf {
			t.Errorf("%s: leaf not cached", host)
		}
	}
}

func TestRefusesHostsOutsideTheSession(t *testing.T) {
	a, err := New([]string{"api.github.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"evil.com", "github.com", "x.api.github.com", "127.0.0.1"} {
		if _, err := a.Certificate(host); err == nil {
			t.Errorf("%s: expected refusal", host)
		}
	}
}

func TestWildcardCoversOnlySubdomains(t *testing.T) {
	a, err := New([]string{"*.githubusercontent.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for host, ok := range map[string]bool{
		"objects.githubusercontent.com":   true,
		"a.b.githubusercontent.com":       true,
		"OBJECTS.githubusercontent.com":   true,
		"githubusercontent.com":           false,
		"evilgithubusercontent.com":       false,
		"githubusercontent.com.evil.test": false,
	} {
		if _, err := a.Certificate(host); (err == nil) != ok {
			t.Errorf("%s: err = %v, want issued = %v", host, err, ok)
		}
	}
}

func TestCertPEMIsTheRoot(t *testing.T) {
	a, err := New([]string{"api.github.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(a.CertPEM())
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("CertPEM = %q", a.CertPEM())
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !root.IsCA || !root.Equal(a.cert) {
		t.Fatalf("root = %+v, %v", root, err)
	}
}

func TestNameConstraintsHoldEvenForForgedLeaves(t *testing.T) {
	a, err := New([]string{"api.github.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	a.permitted = append(a.permitted, "evil.com")
	leaf, err := a.Certificate("evil.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "evil.com", Roots: a.Pool()}); err == nil {
		t.Fatal("name constraints did not stop a leaf for another host")
	}
}

func TestNeedsHosts(t *testing.T) {
	if _, err := New(nil, time.Now); err == nil {
		t.Fatal("want error")
	}
}

func TestTheLeafCacheStaysBounded(t *testing.T) {
	a, err := New([]string{"*.example.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for i := range maxLeaves + 20 {
		if _, err := a.Certificate(fmt.Sprintf("h%d.example.com", i)); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.leaves) > maxLeaves {
		t.Errorf("%d cached leaves, want at most %d", len(a.leaves), maxLeaves)
	}
}
