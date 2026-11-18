package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/fnune/doriath/internal/profile"
	"github.com/fnune/doriath/internal/proxy"
)

type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type guardDialer struct {
	next     proxy.Dialer
	resolver Resolver
	exact    map[string]bool
}

func newGuardDialer(next proxy.Dialer, resolver Resolver, p *profile.Profile) *guardDialer {
	exact := map[string]bool{}
	for _, h := range p.Egress.Allow {
		if !strings.HasPrefix(string(h), "*.") {
			exact[string(h)] = true
		}
	}
	for _, h := range p.HTTP {
		if !strings.HasPrefix(string(h.Host), "*.") {
			exact[string(h.Host)] = true
		}
	}
	return &guardDialer{next: next, resolver: resolver, exact: exact}
}

var errBlockedAddress = errors.New("address not allowed")

func (g *guardDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		addrs, err = g.resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
	}
	lastErr := fmt.Errorf("%s has no address", host)
	for _, a := range addrs {
		if reason := g.refuse(host, a.Unmap()); reason != "" {
			lastErr = fmt.Errorf("%w: %s resolves to %s, %s", errBlockedAddress, host, a, reason)
			continue
		}
		conn, err := g.next.DialContext(ctx, network, net.JoinHostPort(a.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (g *guardDialer) refuse(host string, a netip.Addr) string {
	a = translatedIPv4(a)
	switch {
	case a.IsLoopback():
		return "a loopback address; use [egress] ports for host services"
	case a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast():
		return "a link-local address, where cloud metadata services live"
	case a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast():
		return "not a unicast address"
	case private(a) && !g.exact[host]:
		return "a private address; name the host exactly in the profile to allow it"
	}
	return ""
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func private(a netip.Addr) bool {
	return a.IsPrivate() || slices.ContainsFunc(nonPublic, func(p netip.Prefix) bool { return p.Contains(a) })
}

var (
	nat64  = netip.MustParsePrefix("64:ff9b::/96")
	sixTo4 = netip.MustParsePrefix("2002::/16")
	teredo = netip.MustParsePrefix("2001::/32")
)

func translatedIPv4(a netip.Addr) netip.Addr {
	a = a.Unmap()
	b := a.As16()
	switch {
	case nat64.Contains(a):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	case sixTo4.Contains(a):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
	case teredo.Contains(a):
		return netip.AddrFrom4([4]byte{^b[12], ^b[13], ^b[14], ^b[15]})
	}
	return a
}
