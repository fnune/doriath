package session

import (
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fnune/girdle/internal/approval"
	"github.com/fnune/girdle/internal/profile"
	"github.com/fnune/girdle/internal/proxy"
)

type livePolicy struct {
	*profile.Profile
	mu      sync.RWMutex
	extra   map[string]bool
	learn   bool
	learned map[string]map[string]bool
}

func newLivePolicy(p *profile.Profile, learn bool) *livePolicy {
	return &livePolicy{Profile: p, extra: map[string]bool{}, learn: learn, learned: map[string]map[string]bool{}}
}

func (l *livePolicy) AllowsHostFor(host, exe string) bool {
	if l.Profile.AllowsHostFor(host, exe) {
		return true
	}
	host = strings.ToLower(host)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.extra[host] {
		return true
	}
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && !publicAddr(ip) {
		return false
	}
	if l.learn {
		if l.learned[host] == nil {
			l.learned[host] = map[string]bool{}
		}
		l.learned[host][programName(exe)] = true
	}
	return l.learn
}

// Learned lists the hosts that learning mode let through, sorted.
func (l *livePolicy) Learned() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return slices.Sorted(maps.Keys(l.learned))
}

// LearnedBy groups the learned hosts by the program that reached them. A
// host reached by several programs is listed under each.
func (l *livePolicy) LearnedBy() map[string][]string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := map[string][]string{}
	for _, host := range slices.Sorted(maps.Keys(l.learned)) {
		for prog := range l.learned[host] {
			out[prog] = append(out[prog], host)
		}
	}
	return out
}

func programName(exe string) string {
	if exe == "" {
		return "an unidentified program"
	}
	return strings.TrimSuffix(strings.TrimPrefix(filepath.Base(exe), "."), "-wrapped")
}

func (l *livePolicy) allow(host string) {
	l.mu.Lock()
	l.extra[strings.ToLower(host)] = true
	l.mu.Unlock()
}

const ruleTTL = 30 * time.Minute

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
		Details: fmt.Sprintf("%s tried to reach %s, which the profile does not allow.", who, e.Host) + uploadWarning(e.Host),
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

// openUploadHosts accept data from anyone: object storage, paste and file
// drops, request bins and chat webhooks. Allowing one gives the agent a
// place to send what it reads.
var openUploadHosts = []string{
	"amazonaws.com", "storage.googleapis.com", "blob.core.windows.net", "r2.cloudflarestorage.com",
	"digitaloceanspaces.com", "backblazeb2.com",
	"pastebin.com", "paste.ee", "hastebin.com", "transfer.sh", "file.io", "0x0.st", "termbin.com",
	"webhook.site", "requestbin.com", "pipedream.net", "beeceptor.com", "ngrok.io", "ngrok-free.app",
	"hooks.slack.com", "discord.com", "discordapp.com", "api.telegram.org",
}

func uploadWarning(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range openUploadHosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return " Careful: anyone can upload to " + h + ", so allowing it lets the agent send data out."
		}
	}
	return ""
}
