package session

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fnune/girdle/internal/approval"
	"github.com/fnune/girdle/internal/profile"
	"github.com/fnune/girdle/internal/proxy"
)

// livePolicy is the profile plus hosts the person allowed during this
// session. In learning mode it lets any host through and records the ones
// the profile does not name, so a person can build an allowlist from one
// run instead of one denial at a time.
type livePolicy struct {
	*profile.Profile
	mu      sync.RWMutex
	extra   map[string]bool
	learn   bool
	learned map[string]bool
}

func newLivePolicy(p *profile.Profile, learn bool) *livePolicy {
	return &livePolicy{Profile: p, extra: map[string]bool{}, learn: learn, learned: map[string]bool{}}
}

func (l *livePolicy) AllowsHost(host string) bool {
	if l.Profile.AllowsHost(host) {
		return true
	}
	host = strings.ToLower(host)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.extra[host] {
		return true
	}
	// An address the dialer refuses anyway, such as the cloud metadata
	// service, is never something to add to a profile.
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && !publicAddr(ip) {
		return false
	}
	if l.learn {
		l.learned[host] = true
	}
	return l.learn
}

// Learned lists the hosts that learning mode let through, sorted.
func (l *livePolicy) Learned() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return slices.Sorted(maps.Keys(l.learned))
}

func (l *livePolicy) allow(host string) {
	l.mu.Lock()
	l.extra[strings.ToLower(host)] = true
	l.mu.Unlock()
}

const ruleTTL = 30 * time.Minute

// proposeHost drafts a rule from a denied host. Nothing waits for the
// answer: the agent already got its error, and a retry after the person
// allows the host goes through.
func (s *Session) proposeHost(e proxy.Event) {
	if e.Reason != "host not in the profile" {
		return
	}
	who := "A program"
	if e.Exe != "" {
		who = e.Exe
	}
	req := approval.Request{
		Session: s.id,
		Profile: s.req.Profile.Name,
		Kind:    approval.KindRule,
		Summary: fmt.Sprintf("Allow %s for profile %s?", e.Host, s.req.Profile.Name),
		Details: fmt.Sprintf("%s tried to reach %s, which the profile does not allow.", who, e.Host),
		Scope:   "rule egress " + e.Host,
	}
	s.manager.Propose(req, ruleTTL, func(d approval.Decision) {
		if d.Verdict != approval.VerdictAllow {
			return
		}
		s.policy.allow(e.Host)
		if d.Lasting == approval.LastingProfile {
			if err := profile.AddEgressHost(s.deps.Paths.Profiles(), s.req.Profile.Name, e.Host); err != nil {
				s.log.Write("rule-error", map[string]string{"host": e.Host, "error": err.Error()})
				return
			}
			s.log.Write("rule-added", map[string]string{"host": e.Host, "file": profile.LocalFile(s.req.Profile.Name)})
		}
	})
}

func publicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
}
