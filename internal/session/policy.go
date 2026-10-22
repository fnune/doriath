package session

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fnune/doriath/internal/approval"
	"github.com/fnune/doriath/internal/profile"
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

// pendingTTL keeps a request open for as long as a session plausibly runs:
// you may answer it long after the agent stopped waiting.
const pendingTTL = 12 * time.Hour

// HoldHost asks you about a host the profile does not name, and waits up to
// the configured time. An allow lasts for the session, also when it comes
// after the agent stopped waiting.
func (s *Session) HoldHost(_ context.Context, host, exe string) (bool, string) {
	who := "A program"
	if exe != "" {
		who = exe
	}
	req := approval.Request{
		Session: s.id,
		Profile: s.req.Profile.Name,
		Kind:    approval.KindHost,
		Summary: fmt.Sprintf("Allow %s for profile %s?", host, s.req.Profile.Name),
		Details: fmt.Sprintf("%s tried to reach %s, which the profile does not allow. An allow lasts until the session ends.", who, host) + uploadWarning(host) + "\n" + keepHint(s.req.Profile.Name, []string{host}),
		Scope:   "host egress " + host,
	}
	d, id := s.manager.Hold(req, pendingTTL, s.deps.HostWait, func(d approval.Decision) {
		if d.Verdict == approval.VerdictAllow {
			s.policy.allow(host)
		}
	})
	if d.Verdict == approval.VerdictAllow {
		s.policy.allow(host)
		return true, ""
	}
	if d.Verdict == approval.VerdictDeny {
		return false, ""
	}
	return false, id
}

// keepHint says how to keep hosts for later sessions. doriath does not edit
// profiles: they may come from nix, and you decide their shape.
func keepHint(profile string, hosts []string) string {
	quoted := make([]string, len(hosts))
	for i, h := range hosts {
		quoted[i] = strconv.Quote(h)
	}
	return fmt.Sprintf("To keep it for later sessions, add to profile %s:\n[egress]\nallow = [%s]", profile, strings.Join(quoted, ", "))
}

func publicAddr(ip netip.Addr) bool {
	ip = translatedIPv4(ip)
	return ip.IsGlobalUnicast() && !private(ip)
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
