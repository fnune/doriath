package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/fnune/girdle/internal/profile"
	"github.com/fnune/girdle/internal/proxy"
)

// Resolver looks up the addresses of a host name.
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
	case a.IsPrivate() && !g.exact[host]:
		return "a private address; name the host exactly in the profile to allow it"
	}
	return ""
}

// nat64 is the well-known NAT64 prefix. A gateway translates its addresses
// to the IPv4 address in the last 32 bits, so they are judged by that one.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

func translatedIPv4(a netip.Addr) netip.Addr {
	a = a.Unmap()
	if !nat64.Contains(a) {
		return a
	}
	b := a.As16()
	return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
}
