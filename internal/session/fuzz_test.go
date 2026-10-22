package session

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io/fs"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/fnune/doriath/internal/ca"
	"github.com/fnune/doriath/internal/profile"
	"software.sslmate.com/src/go-pkcs12"
)

func FuzzGuardDialer(f *testing.F) {
	f.Add("public.example.com:443", []byte{93, 184, 216, 34}, false)
	f.Add("metabase.corp.example:443", []byte{10, 1, 2, 3}, true)
	f.Add("sneaky.example.com:443", []byte{10, 1, 2, 3}, false)
	f.Add("meta.example.com:443", []byte{169, 254, 169, 254}, false)
	f.Add("mixed.example.com:443", []byte{127, 0, 0, 1, 93, 184, 216, 35}, false)
	f.Add("[::ffff:127.0.0.1]:443", []byte{}, false)
	f.Add("[fe80::1%eth0]:443", []byte{}, false)
	f.Add("METABASE.corp.example.:443", []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1}, true)
	f.Fuzz(func(t *testing.T, address string, resolved []byte, exact bool) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return
		}
		name := strings.ToLower(strings.TrimSuffix(host, "."))
		p := &profile.Profile{}
		if exact {
			p.Egress.Allow = []profile.HostPattern{profile.HostPattern(name)}
		}
		next := &recordingDialer{}
		g := newGuardDialer(next, fuzzResolver(resolved), p)
		conn, err := g.DialContext(context.Background(), "tcp", address)
		if err == nil {
			_ = conn.Close()
		}
		for _, d := range next.dialed {
			h, dport, err := net.SplitHostPort(d)
			if err != nil || dport != port {
				t.Fatalf("dialed %q for %q", d, address)
			}
			a, err := netip.ParseAddr(h)
			if err != nil {
				t.Fatalf("dialed the name %q for %q, not a resolved address", d, address)
			}
			switch {
			case a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(), a.IsMulticast(), a.IsUnspecified(), a.IsInterfaceLocalMulticast():
				t.Fatalf("dialed %s for %q", d, address)
			case a.IsPrivate() && !exact:
				t.Fatalf("dialed private %s for %q, which the profile does not name exactly", d, address)
			}
		}
	})
}

type fuzzResolver []byte

func (r fuzzResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	var out []netip.Addr
	for rest := []byte(r); len(rest) >= 4; {
		n := 4
		if rest[0]&1 == 1 && len(rest) >= 16 {
			n = 16
		}
		a, _ := netip.AddrFromSlice(rest[:n])
		out = append(out, a)
		rest = rest[n:]
	}
	return out, nil
}

func FuzzPublicAddr(f *testing.F) {
	for _, s := range []string{"93.184.216.34", "10.0.0.1", "::ffff:10.0.0.1", "169.254.169.254", "::1", "fe80::1", "fc00::1", "2001:db8::1", "0.0.0.0", "224.0.0.1"} {
		f.Add(netip.MustParseAddr(s).AsSlice())
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		ip, ok := netip.AddrFromSlice(raw)
		if !ok || !publicAddr(ip) {
			return
		}
		a := ip.Unmap()
		if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
			t.Fatalf("%s counts as public", ip)
		}
	})
}

func FuzzUploadWarning(f *testing.F) {
	f.Add("my-bucket.s3", uint8(0), true, false)
	f.Add("", uint8(13), false, true)
	f.Fuzz(func(t *testing.T, sub string, i uint8, upper, dot bool) {
		host := openUploadHosts[int(i)%len(openUploadHosts)]
		if sub != "" {
			host = sub + "." + host
		}
		if upper {
			host = strings.ToUpper(host)
		}
		if dot {
			host += "."
		}
		if uploadWarning(host) == "" {
			t.Fatalf("no warning for %q", host)
		}
	})
}

func fuzzCA(f *testing.F) []byte {
	authority, err := ca.New([]string{"github.com"}, time.Now)
	if err != nil {
		f.Fatal(err)
	}
	return authority.CertPEM()
}

func certificates(bundle []byte) [][]byte {
	var out [][]byte
	for rest := bundle; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if _, err := x509.ParseCertificate(block.Bytes); block.Type == "CERTIFICATE" && err == nil {
			out = append(out, block.Bytes)
		}
	}
}

func FuzzJavaTrustStore(f *testing.F) {
	cert := fuzzCA(f)
	f.Add(cert)
	f.Add(append([]byte("not a certificate\n"), cert...))
	f.Add(append(append([]byte("-----BEGIN CERTIFICATE-----\n"), cert...), cert...))
	f.Add(bytes.Replace(cert, []byte("CERTIFICATE"), []byte("PRIVATE KEY"), 2))
	f.Add([]byte("nothing"))
	f.Fuzz(func(t *testing.T, bundle []byte) {
		want := certificates(bundle)
		store, err := JavaTrustStore(bundle)
		if len(want) == 0 {
			if err == nil {
				t.Fatal("a trust store without certificates would make Java trust nothing")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		certs, err := pkcs12.DecodeTrustStore(store, JavaTrustStorePassword)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range want {
			found := false
			for _, c := range certs {
				found = found || bytes.Equal(c.Raw, w)
			}
			if !found {
				t.Fatal("the trust store lacks a certificate of the bundle")
			}
		}
	})
}

func FuzzCABundle(f *testing.F) {
	session := fuzzCA(f)
	f.Add([]byte("SYSTEM\n\n"))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n"))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA"))
	f.Add(session[:len(session)-1])
	f.Fuzz(func(t *testing.T, system []byte) {
		read := func(p string) ([]byte, error) {
			if p == caBundleCandidates[0] {
				return system, nil
			}
			return nil, fs.ErrNotExist
		}
		out, err := CABundle(func(string) string { return "" }, read, session)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasSuffix(out, session) {
			t.Fatal("the session CA is not at the end of the bundle")
		}
		sessionDER := certificates(session)[0]
		for _, c := range certificates(out) {
			if bytes.Equal(c, sessionDER) {
				return
			}
		}
		t.Fatalf("the system bundle %q hides the session CA", system)
	})
}
