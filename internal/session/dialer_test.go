package session

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/fnune/girdle/internal/profile"
)

type fakeResolver map[string][]string

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range f[host] {
		out = append(out, netip.MustParseAddr(s))
	}
	if len(out) == 0 {
		return nil, errors.New("no such host")
	}
	return out, nil
}

type recordingDialer struct{ dialed []string }

func (r *recordingDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	r.dialed = append(r.dialed, address)
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, nil
}

func TestGuardDialer(t *testing.T) {
	p := &profile.Profile{Egress: profile.Egress{Allow: []profile.HostPattern{"metabase.corp.example", "*.example.com"}}}
	resolver := fakeResolver{
		"public.example.com":    {"93.184.216.34"},
		"metabase.corp.example": {"10.1.2.3"},
		"sneaky.example.com":    {"10.1.2.3"},
		"meta.example.com":      {"169.254.169.254"},
		"home.example.com":      {"127.0.0.1"},
		"mixed.example.com":     {"127.0.0.1", "93.184.216.35"},
		"nat64.example.com":     {"64:ff9b::a9fe:a9fe"},
		"tailnet.example.com":   {"100.101.102.103"},
		"sixto4.example.com":    {"2002:5db8:d822::1"},
	}
	for addr, want := range map[string]string{
		"public.example.com:443":                     "93.184.216.34:443",
		"metabase.corp.example:443":                  "10.1.2.3:443",
		"mixed.example.com:443":                      "93.184.216.35:443",
		"sneaky.example.com:443":                     "",
		"meta.example.com:443":                       "",
		"home.example.com:443":                       "",
		"169.254.169.254:80":                         "",
		"[::1]:443":                                  "",
		"nat64.example.com:443":                      "",
		"[64:ff9b::7f00:1]:443":                      "",
		"tailnet.example.com:443":                    "",
		"240.0.0.1:443":                              "",
		"255.255.255.255:443":                        "",
		"192.0.0.8:443":                              "",
		"[2002:7f00:1::1]:443":                       "",
		"[2001:0:4136:e378:8000:63bf:80ff:fffe]:443": "",
		"sixto4.example.com:443":                     "[2002:5db8:d822::1]:443",
	} {
		next := &recordingDialer{}
		g := newGuardDialer(next, resolver, p)
		conn, err := g.DialContext(context.Background(), "tcp", addr)
		if want == "" {
			if err == nil || !errors.Is(err, errBlockedAddress) {
				t.Errorf("%s: err = %v, want a blocked address", addr, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", addr, err)
			continue
		}
		_ = conn.Close()
		if len(next.dialed) != 1 || next.dialed[0] != want {
			t.Errorf("%s dialed %v, want %s", addr, next.dialed, want)
		}
	}
}
