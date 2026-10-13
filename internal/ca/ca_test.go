package ca

import (
	"crypto/x509"
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

func TestNameConstraintsHoldEvenForForgedLeaves(t *testing.T) {
	a, err := New([]string{"api.github.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	// Bypass the covers check, as a leaked key would, and check that a
	// verifier still rejects the leaf.
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
