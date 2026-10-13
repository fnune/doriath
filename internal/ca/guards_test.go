package ca

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestAuthorityOnlySignsCertificates(t *testing.T) {
	a, err := New([]string{"api.github.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign; a.cert.KeyUsage != want {
		t.Fatalf("CA key usage = %v, want %v", a.cert.KeyUsage, want)
	}
}

func TestLeafIsReplacedBeforeItExpires(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	a, err := New([]string{"api.github.com"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	first, err := a.Certificate("api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(24 * time.Hour)
	if again, _ := a.Certificate("api.github.com"); again != first {
		t.Fatal("a fresh leaf must be reused")
	}
	now = first.Leaf.NotAfter.Add(-30 * time.Minute)
	renewed, err := a.Certificate("api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	if renewed == first {
		t.Fatal("a leaf within an hour of expiry must be replaced")
	}
	if !now.Before(renewed.Leaf.NotAfter.Add(-time.Hour)) {
		t.Fatalf("renewed leaf expires at %v", renewed.Leaf.NotAfter)
	}
}
