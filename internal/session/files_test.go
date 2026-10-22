package session

import (
	"io/fs"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/ca"
	"software.sslmate.com/src/go-pkcs12"
)

func TestCABundle(t *testing.T) {
	read := func(p string) ([]byte, error) {
		if p == "/etc/ssl/cert.pem" {
			return []byte("SYSTEM\n\n"), nil
		}
		return nil, fs.ErrNotExist
	}
	got, err := CABundle(func(string) string { return "" }, read, []byte("SESSION\n"))
	if err != nil || string(got) != "SYSTEM\nSESSION\n" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := CABundle(func(string) string { return "" }, func(string) ([]byte, error) { return nil, fs.ErrNotExist }, nil); err == nil {
		t.Fatal("want error")
	}
}

func TestJavaTrustStoreHoldsTheBundle(t *testing.T) {
	authority, err := ca.New([]string{"github.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	store, err := JavaTrustStore(append([]byte("not a certificate\n"), authority.CertPEM()...))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := pkcs12.DecodeTrustStore(store, JavaTrustStorePassword)
	if err != nil || len(certs) != 1 || !certs[0].IsCA {
		t.Fatalf("trust store = %v, %v", certs, err)
	}
	if _, err := JavaTrustStore([]byte("nothing")); err == nil {
		t.Error("an empty trust store would make Java trust nothing")
	}
}
